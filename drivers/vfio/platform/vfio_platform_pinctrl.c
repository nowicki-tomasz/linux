// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO platform devices pinctrl handling
 *
 * Copyright (C) 2020 - Semihalf
 * Author: Tomasz Nowicki <tn@semihalf.com>
 */

#include <linux/notifier.h>
#include <linux/gpio/consumer.h>
#include <linux/pinctrl/consumer.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/machine.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/vhost_vfio.h>
#include <linux/virtio_vfio.h>

#include "vfio_platform_private.h"

static int pinctrl_init(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct pinctrl_devres *pinctrl_res = &vdev->pinctrl_res;
	int ret;

	pinctrl_res->pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR(pinctrl_res->pinctrl)) {
		ret = PTR_ERR(pinctrl_res->pinctrl);
		if (ret != -ENODEV) {
			dev_err(dev, "failed to get pinctrl %d\n", ret);
			return ret;
		}
	}
	pinctrl_res->num_pinctrl = pinctrl_count_state(pinctrl_res->pinctrl);
	return 0;
}

static int gpio_init(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct pinctrl_devres *pinctrl_res = &vdev->pinctrl_res;
	int ret;

	ret = devm_gpiod_bulk_get_all(dev, &pinctrl_res->gpio_bulk);
	if (ret < 0) {
		dev_err(dev, "failed to get GPIO %d\n", ret);
		return ret;
	}
	pinctrl_res->num_gpio_func = ret;
	return 0;
}

int vfio_platform_pinctrl_init(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct pinctrl_devres *pinctrl_res = &vdev->pinctrl_res;

	if (pinctrl_init(vdev) || gpio_init(vdev))
		return -ENXIO;

	if (!pinctrl_res->num_pinctrl && !pinctrl_res->num_gpio_func)
		return 0;

	pinctrl_res->vdev = devm_kcalloc(dev, pinctrl_res->num_pinctrl +
					 pinctrl_res->num_gpio_func,
					 sizeof(pinctrl_res->vdev), GFP_KERNEL);
	if (!pinctrl_res->vdev)
		return -ENOMEM;

	return 0;
}

static int vfio_platform_pinctrl_add(struct vfio_platform_device *vdev,
				       struct vhost_dev *vhost, int index)
{
	struct pinctrl_devres *pinctrl_res = &vdev->pinctrl_res;

	pinctrl_res->vdev[index] = vhost;
	return 0;
}

static int vfio_platform_pinctrl_del(struct vfio_platform_device *vdev,
				       struct vhost_dev *vhost, int index)
{
	struct pinctrl_devres *pinctrl_res = &vdev->pinctrl_res;

	pinctrl_res->vdev[index] = NULL;
	return 0;
}

int vfio_platform_pinctrl_register_vhost(struct vfio_platform_device *vdev,
				     struct vhost_dev *vhost, int index,
				     bool add)
{
	struct pinctrl_devres *pinctrl_res = &vdev->pinctrl_res;
	struct device *dev = vdev->device;

	if (index > pinctrl_res->num_pinctrl - 1) {
		dev_err(dev, "Index out of range (index %d > max %d)\n",
			index, pinctrl_res->num_pinctrl - 1);
		return -EINVAL;
	}

	return add ? vfio_platform_pinctrl_add(vdev, vhost, index) :
			vfio_platform_pinctrl_del(vdev, vhost, index);
}

void vfio_platform_pinctrl_cleanup(struct vfio_platform_device *vdev)
{
	struct pinctrl_devres *pinctrl_res = &vdev->pinctrl_res;
	int i, j;

	for (i = 0; i < pinctrl_res->num_gpio_func; i++) {
		for (j = 0; j < pinctrl_res->gpio_bulk[i].ndescs; j++)
			gpiod_put(pinctrl_res->gpio_bulk[i].desc[j]);
	}

	for (i = 0; i < pinctrl_res->num_pinctrl; i++) {
		pinctrl_res->vdev[i] = NULL;
	}
}

static int vfio_platform_pinctrl_resp(struct vfio_vhost_req *req, int errno,
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

int vfio_platform_pinctrl_handle_req(struct vfio_platform_device *vdev,
				     struct vfio_vhost_req *req)
{
	struct virtio_vfio_gpio_dir_input_msg *dir_input;
	struct virtio_vfio_gpio_dir_output_msg *dir_output;
	struct virtio_vfio_pinctrl_dir_msg *dir;
	struct virtio_vfio_pinctrl_val_msg *pin_val;
	struct virtio_vfio_req_hdr *req_hdr;
	struct virtio_vfio_req *req_msg;
	struct pinctrl_state *state;
	struct pinctrl *pinctrl;
	struct gpio_desc *desc;
	uint32_t index;
	uint64_t *return_val;
	int value;
	int ret = 0;

	index = req->dev_idx;
	req_msg = (struct virtio_vfio_req *)req->vq_req;
	req_hdr = (struct virtio_vfio_req_hdr *)req_msg;
	switch (req_hdr->req_type) {
	case VIRTIO_VFIO_REQ_PINCTRL_SELECT:
		if (index > vdev->pinctrl_res.num_pinctrl - 1) {
			dev_err(vdev->device, "Index out of range\n");
			return vfio_platform_pinctrl_resp(req, -EINVAL,
							  VIRTIO_VFIO_S_INVAL);
		}

		pinctrl = vdev->pinctrl_res.pinctrl;
		state = pinctrl_lookup_state_idx(pinctrl, index);
		if (IS_ERR(state)) {
			dev_err(vdev->device, "State does not exist\n");
			return vfio_platform_pinctrl_resp(req, -EINVAL,
							  VIRTIO_VFIO_S_INVAL);
		}

		ret = pinctrl_select_state(pinctrl, state);
		if (ret)
			dev_err(vdev->device, "pinctrl set failed\n");
		break;
	case VIRTIO_VFIO_REQ_GPIO_DIR_IN:
		if (index > vdev->pinctrl_res.num_gpio_func - 1) {
			dev_err(vdev->device, "Index out of range\n");
			return vfio_platform_pinctrl_resp(req, -EINVAL,
							  VIRTIO_VFIO_S_INVAL);
		}

		if (req_hdr->req_len < sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		dir_input = (struct virtio_vfio_gpio_dir_input_msg *)req_msg;
		desc = vdev->pinctrl_res.gpio_bulk[index].desc[dir_input->offset];

		ret = gpiod_direction_input(desc);
		if (ret)
			dev_err(vdev->device, "gpiod_direction_input failed\n");
		break;
	case VIRTIO_VFIO_REQ_GPIO_DIR_OUT:
		if (index > vdev->pinctrl_res.num_gpio_func - 1) {
			dev_err(vdev->device, "Index out of range\n");
			return vfio_platform_pinctrl_resp(req, -EINVAL,
							  VIRTIO_VFIO_S_INVAL);
		}

		if (req_hdr->req_len < 2 * sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		dir_output = (struct virtio_vfio_gpio_dir_output_msg *)req_msg;
		value = dir_output->val;
		desc = vdev->pinctrl_res.gpio_bulk[index].desc[dir_output->offset];

		ret = gpiod_direction_output_raw(desc, value);
		if (ret)
			dev_err(vdev->device, "gpiod_direction_input failed\n");
		break;
	case VIRTIO_VFIO_REQ_GPIO_GET_DIR:
		if (index > vdev->pinctrl_res.num_gpio_func - 1) {
			dev_err(vdev->device, "Index out of range\n");
			return vfio_platform_pinctrl_resp(req, -EINVAL,
							  VIRTIO_VFIO_S_INVAL);
		}

		if (req_hdr->req_len < sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		dir = (struct virtio_vfio_pinctrl_dir_msg *)req_msg;
		return_val = (uint64_t *)req->vq_resp;
		desc = vdev->pinctrl_res.gpio_bulk[index].desc[dir->offset];

		*return_val = gpiod_get_direction(desc);
		break;
	case VIRTIO_VFIO_REQ_GPIO_GET_VAL:
		if (index > vdev->pinctrl_res.num_gpio_func - 1) {
			dev_err(vdev->device, "Index out of range\n");
			return vfio_platform_pinctrl_resp(req, -EINVAL,
							  VIRTIO_VFIO_S_INVAL);
		}

		if (req_hdr->req_len < sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		pin_val = (struct virtio_vfio_pinctrl_val_msg *)req_msg;
		return_val = (uint64_t *)req->vq_resp;
		desc = vdev->pinctrl_res.gpio_bulk[index].desc[pin_val->offset];

		*return_val = gpiod_get_raw_value(desc);
		break;
	case VIRTIO_VFIO_REQ_GPIO_SET_VAL:
		if (index > vdev->pinctrl_res.num_gpio_func - 1) {
			dev_err(vdev->device, "Index out of range\n");
			return vfio_platform_pinctrl_resp(req, -EINVAL,
							  VIRTIO_VFIO_S_INVAL);
		}

		if (req_hdr->req_len < 2 * sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		pin_val = (struct virtio_vfio_pinctrl_val_msg *)req_msg;
		value = pin_val->val;
		desc = vdev->pinctrl_res.gpio_bulk[index].desc[pin_val->offset];
		gpiod_set_raw_value(desc, value);
		break;
	case VIRTIO_VFIO_REQ_GPIO_GET_NR_DESC:
		if (index > vdev->pinctrl_res.num_gpio_func - 1) {
			dev_err(vdev->device, "Index out of range\n");
			return vfio_platform_pinctrl_resp(req, -EINVAL,
							  VIRTIO_VFIO_S_INVAL);
		}

		return_val = (uint64_t *)req->vq_resp;
		*return_val = vdev->pinctrl_res.gpio_bulk[index].ndescs;
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return vfio_platform_pinctrl_resp(req, ret,
					  ret ? VIRTIO_VFIO_S_IOERR : 0);
}
