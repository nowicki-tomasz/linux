// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO platform devices clock handling
 *
 * Copyright (C) 2020 - Semihalf
 * Author: Tomasz Nowicki <tn@semihalf.com>
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/virtio_vfio.h>
#include <linux/vfio.h>

#include "vfio_platform_private.h"

int vfio_platform_clk_init(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	int ret;

	ret = devm_clk_bulk_get_all(dev, &vdev->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get clocks %d\n", ret);
		return ret;
	}
	vdev->num_clks = ret;
	return 0;
}

static int vfio_platform_clk_resp(struct vfio_req *req, int errno,
				  int vhost_err)
{
	struct virtio_vfio_req_hdr *req_hdr = (struct virtio_vfio_req_hdr *)req->vq_req;
	struct virtio_vfio_resp_status *status;

	/* Skip buffer space */
	status = (struct virtio_vfio_resp_status *)(req->vq_resp + req_hdr->resp_len - sizeof(*status));
	status->status = vhost_err;
	return errno;
}

int vfio_platform_clk_handle_req(struct vfio_platform_device *vdev,
				 struct vfio_req *req)
{
	struct virtio_vfio_req *req_msg = (struct virtio_vfio_req *)req->vq_req;
	struct virtio_vfio_req_hdr *req_hdr = (struct virtio_vfio_req_hdr *)req_msg;
	uint32_t index = req->index;
	size_t status_sz = sizeof(struct virtio_vfio_resp_status);
	uint64_t set_rate, *get_rate, *flags;
	int ret = 0;

	if (index > vdev->num_clks - 1) {
		dev_err(vdev->device, "Request index violations\n");
		return vfio_platform_clk_resp(req, -EINVAL,
					      VIRTIO_VFIO_S_INVAL);
	}

	switch (req_hdr->req_type) {
	case VIRTIO_VFIO_REQ_CLK_ENABLE:
		ret = clk_enable(vdev->clks[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_DISABLE:
		clk_disable(vdev->clks[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_PREPARE:
		ret = clk_prepare(vdev->clks[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_UNPREPARE:
		clk_unprepare(vdev->clks[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_GET_RATE:
		if (req_hdr->resp_len - status_sz < sizeof(*get_rate)) {
			ret = -EINVAL;
			break;
		}

		get_rate = (uint64_t *)req->vq_resp;
		*get_rate = clk_get_rate(vdev->clks[index].clk);
		break;
	case VIRTIO_VFIO_REQ_CLK_SET_RATE:
		if (req_hdr->req_len < sizeof(set_rate)) {
			ret = -EINVAL;
			break;
		}

		set_rate = ((uint64_t *)req_msg->buf)[0];
		ret = clk_set_rate(vdev->clks[index].clk, set_rate);
		if (ret)
			dev_err(vdev->device, "clock set rate failed\n");
		break;
	case VIRTIO_VFIO_REQ_CLK_GET_FLAGS:
		if (req_hdr->resp_len - status_sz < sizeof(*flags)) {
			ret = -EINVAL;
			break;
		}

		flags = (uint64_t *)req->vq_resp;
		*flags = __clk_get_flags(vdev->clks[index].clk);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return vfio_platform_clk_resp(req, ret,
				      ret ? VIRTIO_VFIO_S_IOERR : 0);
}
