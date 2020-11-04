// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO platform devices pinctrl handling
 *
 * Copyright (C) 2020 - Semihalf
 * Author: Tomasz Nowicki <tn@semihalf.com>
 */

#include <linux/notifier.h>
#include <linux/pinctrl/consumer.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/machine.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/vhost_vfio.h>
#include <linux/virtio_vfio.h>

#include "vfio_platform_private.h"

int vfio_platform_pinctrl_init(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct pinctrl_devres *pinctrl_res = &vdev->pinctrl_res;
	int ret;

	pinctrl_res->pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR(pinctrl_res->pinctrl)) {
		ret = PTR_ERR(pinctrl_res->pinctrl);
		dev_err(dev, "failed to get pinctrl %d\n", ret);
		return ret != -ENODEV ? ret : 0;
	}
	pinctrl_res->num_pinctrl = pinctrl_count_state(pinctrl_res->pinctrl);

	if (!pinctrl_res->num_pinctrl)
		return 0;

	pinctrl_res->vdev = devm_kcalloc(dev, pinctrl_res->num_pinctrl,
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
	int i;

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
	struct virtio_vfio_req_hdr *req_hdr;
	struct virtio_vfio_req *req_msg;
	struct pinctrl_state *state;
	uint32_t index;
	int ret = 0;

	index = req->dev_idx;

	if (index > vdev->pinctrl_res.num_pinctrl - 1) {
		dev_err(vdev->device, "Index out of range\n");
		return vfio_platform_pinctrl_resp(req, -EINVAL,
						    VIRTIO_VFIO_S_INVAL);
	}

	state = pinctrl_lookup_state_idx(vdev->pinctrl_res.pinctrl, index);
	if (IS_ERR(state)) {
		dev_err(vdev->device, "State does not exist\n");
		return vfio_platform_pinctrl_resp(req, -EINVAL,
						    VIRTIO_VFIO_S_INVAL);
	}

	req_msg = (struct virtio_vfio_req *)req->vq_req;
	req_hdr = (struct virtio_vfio_req_hdr *)req_msg;
	switch (req_hdr->req_type) {
	case VIRTIO_VFIO_REQ_PINCTRL_SELECT:
		ret = pinctrl_select_state(vdev->pinctrl_res.pinctrl, state);
		if (ret)
			dev_err(vdev->device, "pinctrl set failed\n");
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return vfio_platform_pinctrl_resp(req, ret,
					  ret ? VIRTIO_VFIO_S_IOERR : 0);
}
