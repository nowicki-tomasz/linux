// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO platform devices clock handling
 *
 * Copyright (C) 2020 - Semihalf
 * Author: Tomasz Nowicki <tn@semihalf.com>
 */

#include <linux/notifier.h>
#include <linux/interconnect.h>
#include <linux/interconnect-provider.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/vhost_vfio.h>
#include <linux/virtio_vfio.h>

#include "vfio_platform_private.h"

int vfio_platform_intercon_init(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct intercon_devres *intercon_res = &vdev->intercon_res;
	int ret;

	ret = devm_icc_bulk_get_all(dev, &intercon_res->path_bulk);
	if (ret < 0) {
		dev_err(dev, "failed to get interconnect %d\n", ret);
		return ret;
	}
	intercon_res->num_intercon = ret;

	if (!intercon_res->num_intercon)
		return 0;

	intercon_res->vdev = devm_kcalloc(dev, intercon_res->num_intercon,
				     sizeof(intercon_res->vdev), GFP_KERNEL);
	if (!intercon_res->vdev)
		return -ENOMEM;

	return 0;
}

static int vfio_platform_intercon_add(struct vfio_platform_device *vdev,
				       struct vhost_dev *vhost, int index)
{
	struct intercon_devres *intercon_res = &vdev->intercon_res;

	intercon_res->vdev[index] = vhost;
	return 0;
}

static int vfio_platform_intercon_del(struct vfio_platform_device *vdev,
				       struct vhost_dev *vhost, int index)
{
	struct intercon_devres *intercon_res = &vdev->intercon_res;

	intercon_res->vdev[index] = NULL;
	return 0;
}

int vfio_platform_intercon_register_vhost(struct vfio_platform_device *vdev,
				     struct vhost_dev *vhost, int index,
				     bool add)
{
	struct intercon_devres *intercon_res = &vdev->intercon_res;
	struct device *dev = vdev->device;

	if (index > intercon_res->num_intercon - 1) {
		dev_err(dev, "Index out of range (index %d > max %d)\n",
			index, intercon_res->num_intercon - 1);
		return -EINVAL;
	}

	return add ? vfio_platform_intercon_add(vdev, vhost, index) :
			vfio_platform_intercon_del(vdev, vhost, index);
}

void vfio_platform_intercon_cleanup(struct vfio_platform_device *vdev)
{
	struct intercon_devres *intercon_res = &vdev->intercon_res;
	int i;

	for (i = 0; i < intercon_res->num_intercon; i++) {
		intercon_res->vdev[i] = NULL;
	}
}

static int vfio_platform_intercon_resp(struct vfio_vhost_req *req, int errno,
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

int vfio_platform_intercon_handle_req(struct vfio_platform_device *vdev,
				   struct vfio_vhost_req *req)
{
	struct virtio_vfio_req_hdr *req_hdr;
	struct virtio_vfio_inter_set *msg;
	struct virtio_vfio_req *req_msg;
	struct icc_path *path;
	size_t status_sz;
	uint32_t index;
	int ret = 0;

	index = req->dev_idx;

	dev_err(vdev->device, "%s request index %d\n", __func__, index);

	if (index > vdev->intercon_res.num_intercon - 1) {
		dev_err(vdev->device, "Index out of range\n");
		return vfio_platform_intercon_resp(req, -EINVAL,
						    VIRTIO_VFIO_S_INVAL);
	}

	path = vdev->intercon_res.path_bulk[index].icc_path;
	req_msg = (struct virtio_vfio_req *)req->vq_req;
	req_hdr = (struct virtio_vfio_req_hdr *)req_msg;
	status_sz = sizeof(struct virtio_vfio_resp_status);

	dev_err(vdev->device, "%s req_hdr->req_type %d\n", __func__, req_hdr->req_type);

	switch (req_hdr->req_type) {
	case VIRTIO_VFIO_REQ_INTER_SET:
		if (req_hdr->req_len < 2 * sizeof(uint64_t)) {
			ret = -EINVAL;
			break;
		}

		msg = (struct virtio_vfio_inter_set *)req_msg;
		dev_err(vdev->device, "interconnect set avg %ld peak %ld\n",
			(long)msg->avg_bw, (long)msg->peak_bw);

		ret = icc_set_bw(path, msg->avg_bw, msg->peak_bw);
		if (ret)
			dev_err(vdev->device, "interconnect set failed\n");
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return vfio_platform_intercon_resp(req, ret,
					    ret ? VIRTIO_VFIO_S_IOERR : 0);
}
