// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO platform devices PHY handling
 *
 * Copyright (C) 2020 - Semihalf
 * Author: Tomasz Nowicki <tn@semihalf.com>
 */

#include <linux/notifier.h>
#include <linux/phy/phy.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/vhost_vfio.h>
#include <linux/virtio_vfio.h>

#include "vfio_platform_private.h"

int vfio_platform_phy_init(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct phy_devres *phy_res = &vdev->phy_res;
	int ret;

	if (!strcmp(dev_name(vdev->device), "ae94000.dsi")) {
		dev_err(dev, "phy: skipped for dev %s\n", dev_name(vdev->device));
		phy_res->num_phy = 0;
		return 0;
	}

	ret = devm_phy_bulk_get_all(dev, &phy_res->phy_bulk);
	if (ret < 0) {
		dev_err(dev, "failed to get interconnect %d\n", ret);
		return ret;
	}
	phy_res->num_phy = ret;

	if (!phy_res->num_phy)
		return 0;

	phy_res->vdev = devm_kcalloc(dev, phy_res->num_phy,
				     sizeof(phy_res->vdev), GFP_KERNEL);
	if (!phy_res->vdev)
		return -ENOMEM;

	return 0;
}

static int vfio_platform_phy_add(struct vfio_platform_device *vdev,
				       struct vhost_dev *vhost, int index)
{
	struct phy_devres *phy_res = &vdev->phy_res;

	phy_res->vdev[index] = vhost;
	return 0;
}

static int vfio_platform_phy_del(struct vfio_platform_device *vdev,
				       struct vhost_dev *vhost, int index)
{
	struct phy_devres *intercon_res = &vdev->phy_res;

	intercon_res->vdev[index] = NULL;
	return 0;
}

int vfio_platform_phy_register_vhost(struct vfio_platform_device *vdev,
				     struct vhost_dev *vhost, int index,
				     bool add)
{
	struct phy_devres *phy_res = &vdev->phy_res;
	struct device *dev = vdev->device;

	if (index > phy_res->num_phy - 1) {
		dev_err(dev, "%s: Index out of range (index %d > max %d)\n",
			__func__, index, phy_res->num_phy - 1);
		return -EINVAL;
	}

	return add ? vfio_platform_phy_add(vdev, vhost, index) :
			vfio_platform_phy_del(vdev, vhost, index);
}

void vfio_platform_phy_cleanup(struct vfio_platform_device *vdev)
{
	struct phy_devres *intercon_res = &vdev->phy_res;
	int i;

	for (i = 0; i < intercon_res->num_phy; i++) {
		intercon_res->vdev[i] = NULL;
	}
}

static int vfio_platform_phy_resp(struct vfio_vhost_req *req, int errno,
				  int vhost_err)
{
	struct virtio_vfio_req_hdr *req_hdr =
				(struct virtio_vfio_req_hdr *)req->vq_req;
	struct virtio_vfio_resp_status *status;

	/* Skip buffer space */
	status = (struct virtio_vfio_resp_status *)(req->vq_resp +
					req_hdr->resp_len - sizeof(*status));
	status->status = vhost_err;

	if (errno)
		pr_err("%s errno %d\n", __func__, errno);

	return errno;
}

int vfio_platform_phy_handle_req(struct vfio_platform_device *vdev,
				   struct vfio_vhost_req *req)
{
	struct virtio_vfio_req_hdr *req_hdr;
	struct virtio_vfio_phy_msg *msg;
	struct virtio_vfio_req *req_msg;
	struct phy *phy;
	uint64_t mode, submode;
	size_t status_sz;
	uint32_t index;
	int ret = 0;

	index = req->dev_idx;

	if (index > vdev->phy_res.num_phy - 1) {
		dev_err(vdev->device, "%s: Index out of range\n", __func__);
		return vfio_platform_phy_resp(req, -EINVAL,
						    VIRTIO_VFIO_S_INVAL);
	}

	phy = vdev->phy_res.phy_bulk[index].phy;
	req_msg = (struct virtio_vfio_req *)req->vq_req;
	req_hdr = (struct virtio_vfio_req_hdr *)req_msg;
	status_sz = sizeof(struct virtio_vfio_resp_status);

	msg = (struct virtio_vfio_phy_msg *)req_msg;
	switch (req_hdr->req_type) {
	case VIRTIO_VFIO_REQ_PHY_INIT:
		ret = phy_init(phy);
		if (ret)
			dev_err(vdev->device, "phy_init failed\n");
		break;
	case VIRTIO_VFIO_REQ_PHY_EXIT:
		ret = phy_exit(phy);
		if (ret)
			dev_err(vdev->device, "phy_exit failed\n");
		break;
	case VIRTIO_VFIO_REQ_PHY_SET_MODE:
		if (req_hdr->req_len < 2 * sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}
		mode = ((uint64_t *)req_msg->buf)[0];
		submode = ((uint64_t *)req_msg->buf)[1];
		ret = phy_set_mode_ext(phy, mode, submode);
		if (ret)
			dev_err(vdev->device, "phy_set_mode_ext failed\n");
		break;
	case VIRTIO_VFIO_REQ_PHY_POWER_ON:
		ret = phy_power_on(phy);
		if (ret)
			dev_err(vdev->device, "phy_power_on failed\n");
		break;
	case VIRTIO_VFIO_REQ_PHY_POWER_OFF:
		ret = phy_power_off(phy);
		if (ret)
			dev_err(vdev->device, "phy_power_off failed\n");
		break;
	case VIRTIO_VFIO_REQ_PHY_RESET:
		ret = phy_reset(phy);
		if (ret)
			dev_err(vdev->device, "phy_reset failed\n");
		break;
	case VIRTIO_VFIO_REQ_PHY_CALIBRATE:
		ret = phy_calibrate(phy);
		if (ret)
			dev_err(vdev->device, "phy_calibrate failed\n");
		break;
	case VIRTIO_VFIO_REQ_PHY_RELEASE:
		phy_put(phy);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return vfio_platform_phy_resp(req, ret,
					    ret ? VIRTIO_VFIO_S_IOERR : 0);
}
