// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO platform devices clock handling
 *
 * Copyright (C) 2020 - Semihalf
 * Author: Tomasz Nowicki <tn@semihalf.com>
 */

#include <linux/notifier.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/driver.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/vhost_vfio.h>
#include <linux/virtio_vfio.h>

#include "vfio_platform_private.h"

//static int vfio_platform_regulator_notifier_cb(struct notifier_block *nb,
//					 unsigned long event, void *data)
//{
//	struct vfio_platform_device *pvdev = container_of(nb,
//						struct vfio_platform_device,
//						clk_nb);
//	struct clk_devres *clk_res = &pvdev->clk_res;
//	struct clk_notifier_data *cnd = data;
//	struct virtio_vfio_clk_event evt = {
//			.msg = event,
//			.old_rate = cnd->old_rate,
//			.new_rate = cnd->new_rate,
//	};
//	struct vhost_dev *vhost;
//	int index, found = 0;
//
//	for (index = 0; index < clk_res->num_clks; index++) {
//		if (clk_res->clk_bulk[index].clk == cnd->clk) {
//			found = 1;
//			break;
//		}
//	}
//
//	if (WARN_ON(found == 0))
//		return NOTIFY_BAD;
//
//	vhost = clk_res->vdev[index];
//	if (!vhost)
//		return NOTIFY_OK;
//
//	return vhost_vfio_send_evt(vhost, &evt, sizeof(evt));
//}

int vfio_platform_regulator_init(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct regulator_devres *regulator_res = &vdev->regulator_res;
	int ret;

	ret = devm_regulator_bulk_get_all(dev, &regulator_res->regulator_bulk);
	if (ret < 0) {
		dev_err(dev, "failed to get regulator %d\n", ret);
		return ret;
	}
	regulator_res->num_regulators = ret;

	if (!regulator_res->num_regulators)
		return 0;

	regulator_res->vdev = devm_kcalloc(dev, regulator_res->num_regulators,
				     sizeof(regulator_res->vdev), GFP_KERNEL);
	if (!regulator_res->vdev)
		return -ENOMEM;

//	vdev->clk_nb.notifier_call = vfio_platform_clk_notifier_cb;

	return 0;
}

static int vfio_platform_regulator_add(struct vfio_platform_device *vdev,
				       struct vhost_dev *vhost, int index)
{
	struct regulator_devres *regulator_res = &vdev->regulator_res;
//	struct device *dev = vdev->device;
//	int ret;
//
//	ret = clk_notifier_register(regulator_res->clk_bulk[index].clk,
//				    &vdev->clk_nb);
//	if (ret) {
//		dev_err(dev, "failed to register clock notifier (err = %d)\n",
//			ret);
//		return ret;
//	}

	regulator_res->vdev[index] = vhost;
	return 0;
}

static int vfio_platform_regulator_del(struct vfio_platform_device *vdev,
				       struct vhost_dev *vhost, int index)
{
	struct regulator_devres *regulator_res = &vdev->regulator_res;

//	clk_notifier_unregister(clk_res->clk_bulk[index].clk, &vdev->clk_nb);
	regulator_res->vdev[index] = NULL;
	return 0;
}

int vfio_platform_regulator_register_vhost(struct vfio_platform_device *vdev,
				     struct vhost_dev *vhost, int index,
				     bool add)
{
	struct regulator_devres *regulator_res = &vdev->regulator_res;
	struct device *dev = vdev->device;

	if (index > regulator_res->num_regulators - 1) {
		dev_err(dev, "%s: Index out of range (index %d > max %d)\n",
			__func__, index, regulator_res->num_regulators - 1);
		return -EINVAL;
	}

	return add ? vfio_platform_regulator_add(vdev, vhost, index) :
		     vfio_platform_regulator_del(vdev, vhost, index);
}

void vfio_platform_regulator_cleanup(struct vfio_platform_device *vdev)
{
	struct regulator_devres *regulator_res = &vdev->regulator_res;
	int i;

	regulator_bulk_free(regulator_res->num_regulators,
			    regulator_res->regulator_bulk);
	for (i = 0; i < regulator_res->num_regulators; i++) {
//		clk_notifier_unregister(vdev->regulator_res.clk_bulk[i].clk,
//					&vdev->clk_nb);
		regulator_res->vdev[i] = NULL;
	}
}

static int vfio_platform_regulator_resp(struct vfio_vhost_req *req, int errno,
				  int vhost_err)
{
	struct virtio_vfio_req_hdr *req_hdr =
				(struct virtio_vfio_req_hdr *)req->vq_req;
	struct virtio_vfio_resp_status *status;

	/* Skip buffer space */
	status = (struct virtio_vfio_resp_status *)(req->vq_resp +
					req_hdr->resp_len - sizeof(*status));
	status->status = vhost_err;
	return errno;
}

int regulator_set_mode_nocheck(struct regulator *regulator, unsigned int mode);

int vfio_platform_regulator_handle_req(struct vfio_platform_device *vdev,
				       struct vfio_vhost_req *req)
{
	struct virtio_vfio_req_hdr *req_hdr;
	struct virtio_vfio_req *req_msg;
	struct regulator *consumer;
	size_t status_sz;
	uint32_t index;
	struct virtio_vfio_regulator_set_cur_limit *set_cur_limit;
	struct virtio_vfio_regulator_list_voltage *list_vol;
	struct virtio_vfio_regulator_map_voltage *map_vol;
	struct virtio_vfio_regulator_set_voltage *set_vol;
	struct virtio_vfio_regulator_set_load *set_load;
	struct virtio_vfio_regulator_set_mode *set_mode;
	uint64_t *is_enabled, *get_cur_limit, *vol, *selector, *n_voltage,
		*type;
	int ret = 0;

	index = req->dev_idx;

	if (index > vdev->regulator_res.num_regulators - 1) {
		dev_err(vdev->device, "%s: Index out of range\n", __func__);
		return vfio_platform_regulator_resp(req, -EINVAL,
						    VIRTIO_VFIO_S_INVAL);
	}

	consumer = vdev->regulator_res.regulator_bulk[index].consumer;
	req_msg = (struct virtio_vfio_req *)req->vq_req;
	req_hdr = (struct virtio_vfio_req_hdr *)req_msg;
	status_sz = sizeof(struct virtio_vfio_resp_status);

	switch (req_hdr->req_type) {
	case VIRTIO_VFIO_REQ_REGULATOR_GET_TYPE:
		if (req_hdr->resp_len - status_sz < sizeof(*type)) {
			ret = -EINVAL;
			break;
		}

		type = (uint64_t *)req->vq_resp;
		*type = REGULATOR_VOLTAGE;
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_GET_N_VOLTAGES:
		if (req_hdr->resp_len - status_sz < sizeof(*n_voltage)) {
			ret = -EINVAL;
			break;
		}

		n_voltage = (uint64_t *)req->vq_resp;
		*n_voltage = regulator_count_voltages(consumer);
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_ENABLE:
		ret = regulator_enable(consumer);
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_DISABLE:
		ret = regulator_disable(consumer);
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_IS_ENABLED:
		if (req_hdr->resp_len - status_sz < sizeof(*is_enabled)) {
			ret = -EINVAL;
			break;
		}

		is_enabled = (uint64_t *)req->vq_resp;
		*is_enabled = regulator_is_enabled(consumer);
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_GET_CUR_LIMIT:
		if (req_hdr->resp_len - status_sz < sizeof(*get_cur_limit)) {
			ret = -EINVAL;
			break;
		}

		get_cur_limit = (uint64_t *)req->vq_resp;
		*get_cur_limit = regulator_get_current_limit(consumer);
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_SET_CUR_LIMIT:
		if (req_hdr->req_len < 2 * sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		set_cur_limit =
			(struct virtio_vfio_regulator_set_cur_limit *)req_msg;
		ret = regulator_set_current_limit(consumer,
						  set_cur_limit->min_uA,
						  set_cur_limit->max_uA);
		if (ret)
			dev_err(vdev->device, "regulator_set_current_limit failed\n");
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_LIST_VOLTAGE:
		if (req_hdr->req_len < sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		list_vol = (struct virtio_vfio_regulator_list_voltage *)req_msg;
		vol = (uint64_t *)req->vq_resp;
		*vol = regulator_list_voltage(consumer, list_vol->selector);
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_MAP_VOLTAGE:
		if (req_hdr->req_len < 2 * sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		map_vol = (struct virtio_vfio_regulator_map_voltage *)req_msg;
		selector = (uint64_t *)req->vq_resp;
		*selector = regulator_get_map_voltage(consumer,
						      map_vol->min_uV,
						      map_vol->max_uV);
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_GET_VOLTAGE:
		if (req_hdr->resp_len - status_sz < sizeof(*vol)) {
			ret = -EINVAL;
			break;
		}

		vol = (uint64_t *)req->vq_resp;
		*vol = regulator_get_voltage(consumer);
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_SET_VOLTAGE:
		if (req_hdr->req_len < 2 * sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		set_vol = (struct virtio_vfio_regulator_set_voltage *)req_msg;
		selector = (uint64_t *)req->vq_resp;
		ret = regulator_set_voltage(consumer, set_vol->min_uV,
					    set_vol->max_uV);
		if (ret) {
			ret = -EINVAL;
			dev_err(vdev->device, "regulator_set_voltage failed\n");
			break;
		}

		*selector = regulator_get_map_voltage(consumer,
						      set_vol->min_uV,
						      set_vol->max_uV);
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_SET_LOAD:
		if (req_hdr->req_len < sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		set_load = (struct virtio_vfio_regulator_set_load *)req_msg;
		ret = regulator_set_load(consumer, set_load->load_uA);
		if (ret)
			dev_err(vdev->device, "regulator_set_load failed\n");
		break;
	case VIRTIO_VFIO_REQ_REGULATOR_SET_MODE:
		if (req_hdr->req_len < sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		set_mode = (struct virtio_vfio_regulator_set_mode *)req_msg;
		ret = regulator_set_mode_nocheck(consumer, set_mode->mode);
		if (ret)
			dev_err(vdev->device, "regulator_set_mode_nocheck failed\n");
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return vfio_platform_regulator_resp(req, ret,
					    ret ? VIRTIO_VFIO_S_IOERR : 0);
}
