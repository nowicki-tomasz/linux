// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO platform devices clock handling
 *
 * Copyright (C) 2020 - Semihalf
 * Author: Tomasz Nowicki <tn@semihalf.com>
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/notifier.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/vhost_vfio.h>
#include <linux/virtio_vfio.h>

#include "vfio_platform_private.h"

static int vfio_platform_clk_notifier_cb(struct notifier_block *nb,
					 unsigned long event, void *data)
{
	struct vfio_platform_device *pvdev = container_of(nb,
						struct vfio_platform_device,
						clk_nb);
	struct clk_devres *clk_res = &pvdev->clk_res;
	struct clk_notifier_data *cnd = data;
	struct virtio_vfio_clk_event evt = {
			.msg = event,
			.old_rate = cnd->old_rate,
			.new_rate = cnd->new_rate,
	};
	struct vhost_dev *vhost;
	int index, found = 0;

	for (index = 0; index < clk_res->num_clks; index++) {
		if (clk_res->clk_bulk[index].clk == cnd->clk) {
			found = 1;
			break;
		}
	}

	if (WARN_ON(found == 0))
		return NOTIFY_BAD;

	vhost = clk_res->vdev[index];
	if (!vhost)
		return NOTIFY_OK;

	return vhost_vfio_send_evt(vhost, &evt, sizeof(evt));
}

int vfio_platform_clk_init(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct clk_devres *clk_res = &vdev->clk_res;
	int ret;

	ret = devm_clk_bulk_get_all(dev, &clk_res->clk_bulk);
	if (ret < 0) {
		dev_err(dev, "failed to get clocks %d\n", ret);
		return ret;
	}
	clk_res->num_clks = ret;

	clk_res->vdev = devm_kcalloc(dev, clk_res->num_clks,
				     sizeof(clk_res->vdev), GFP_KERNEL);
	if (!clk_res->vdev)
		return -ENOMEM;

	vdev->clk_nb.notifier_call = vfio_platform_clk_notifier_cb;

	return 0;
}

static int vfio_platform_clk_add(struct vfio_platform_device *vdev,
				 struct vhost_dev *vhost, int index)
{
	struct clk_devres *clk_res = &vdev->clk_res;
	struct device *dev = vdev->device;
	int ret;

	ret = clk_notifier_register(clk_res->clk_bulk[index].clk,
				    &vdev->clk_nb);
	if (ret) {
		dev_err(dev, "failed to register clock notifier (err = %d)\n",
			ret);
		return ret;
	}

	clk_res->vdev[index] = vhost;
	return 0;
}

static int vfio_platform_clk_del(struct vfio_platform_device *vdev,
				 struct vhost_dev *vhost, int index)
{
	struct clk_devres *clk_res = &vdev->clk_res;

	clk_notifier_unregister(clk_res->clk_bulk[index].clk, &vdev->clk_nb);
	clk_res->vdev[index] = NULL;
	return 0;
}

int vfio_platform_clk_register_vhost(struct vfio_platform_device *vdev,
				     struct vhost_dev *vhost, int index,
				     bool add)
{
	struct clk_devres *clk_res = &vdev->clk_res;
	struct device *dev = vdev->device;

	if (index > clk_res->num_clks - 1) {
		dev_err(dev, "Index out of range (index %d > max %d)\n",
			index, clk_res->num_clks - 1);
		return -EINVAL;
	}

	return add ? vfio_platform_clk_add(vdev, vhost, index) :
		     vfio_platform_clk_del(vdev, vhost, index);
}

void vfio_platform_clk_cleanup(struct vfio_platform_device *vdev)
{
	int i;

	for (i = 0; i < vdev->clk_res.num_clks; i++) {
		clk_notifier_unregister(vdev->clk_res.clk_bulk[i].clk,
					&vdev->clk_nb);
	}
}

static int vfio_platform_clk_resp(struct vfio_vhost_req *req, int errno,
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

int vfio_platform_clk_handle_req(struct vfio_platform_device *vdev,
				 struct vfio_vhost_req *req)
{
	struct virtio_vfio_req *req_msg = (struct virtio_vfio_req *)req->vq_req;
	struct virtio_vfio_req_hdr *req_hdr =
					(struct virtio_vfio_req_hdr *)req_msg;
	uint32_t index = req->dev_idx;
	size_t status_sz = sizeof(struct virtio_vfio_resp_status);
	struct clk_bulk_data *clk_bulk = vdev->clk_res.clk_bulk;
	uint64_t set_rate, *get_rate, *flags;
	int ret = 0;

	if (index > vdev->clk_res.num_clks - 1) {
		dev_err(vdev->device, "Index out of range\n");
		return vfio_platform_clk_resp(req, -EINVAL,
					      VIRTIO_VFIO_S_INVAL);
	}

	switch (req_hdr->req_type) {
	case VIRTIO_VFIO_REQ_CLK_ENABLE:
		ret = clk_enable(clk_bulk[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_DISABLE:
		clk_disable(clk_bulk[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_PREPARE:
		ret = clk_prepare(clk_bulk[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_UNPREPARE:
		clk_unprepare(clk_bulk[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_RECALC_RATE:
		if (req_hdr->resp_len - status_sz < sizeof(*get_rate)) {
			ret = -EINVAL;
			break;
		}

		get_rate = (uint64_t *)req->vq_resp;
		*get_rate = clk_get_rate_recalc(clk_bulk[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_SET_RATE:
		if (req_hdr->req_len < sizeof(set_rate)) {
			ret = -EINVAL;
			break;
		}

		set_rate = ((uint64_t *)req_msg->buf)[0];
		ret = clk_set_rate(clk_bulk[index].clk, set_rate);
		if (ret)
			dev_err(vdev->device, "clock set rate failed\n");
		break;
	case VIRTIO_VFIO_REQ_CLK_GET_FLAGS:
		if (req_hdr->resp_len - status_sz < sizeof(*flags)) {
			ret = -EINVAL;
			break;
		}

		flags = (uint64_t *)req->vq_resp;
		*flags = __clk_get_flags(clk_bulk[index].clk);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return vfio_platform_clk_resp(req, ret,
				      ret ? VIRTIO_VFIO_S_IOERR : 0);
}
