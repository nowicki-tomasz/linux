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

int vfio_platform_clk_ioctl(unsigned long arg,
			    struct vfio_platform_device *vdev,
			    struct vfio_clk *hdr)
{
	uint64_t *set_rate, get_rate, flags;
	unsigned long minsz;
	int ret = 0;

	if (hdr->index < 0 || hdr->index > vdev->num_clks - 1)
		return -EINVAL;

	switch (hdr->flags) {
	case VFIO_CLK_ENABLE:
		ret = clk_enable(vdev->clks[hdr->index].clk);
		break;
	case VFIO_CLK_DISABLE:
		clk_disable(vdev->clks[hdr->index].clk);
		break;
	case VFIO_CLK_PREPARE:
		ret = clk_prepare(vdev->clks[hdr->index].clk);
		break;
	case VFIO_CLK_UNPREPARE:
		clk_unprepare(vdev->clks[hdr->index].clk);
		break;
	case VFIO_CLK_GET_RATE:
		minsz = offsetofend(struct vfio_clk, index);

		if (hdr->argsz - minsz < sizeof(get_rate))
			return -EINVAL;

		get_rate = clk_get_rate(vdev->clks[hdr->index].clk);


		ret = copy_to_user((void __user *)arg + minsz, &get_rate,
				   sizeof(get_rate)) ? -EFAULT : 0;

		break;
	case VFIO_CLK_SET_RATE:
		minsz = offsetofend(struct vfio_clk, index);

		if (hdr->argsz - minsz < sizeof(*set_rate))
			return -EINVAL;

		set_rate = memdup_user((void __user *)(arg + minsz),
				    hdr->argsz - minsz);
		if (IS_ERR(set_rate))
			return PTR_ERR(set_rate);

		ret = clk_set_rate(vdev->clks[hdr->index].clk, *set_rate);
		if (ret)
			dev_err(vdev->device, "clock set rate failed\n");

		kfree(set_rate);
		break;
	case VFIO_CLK_GET_FLAGS:
		minsz = offsetofend(struct vfio_clk, index);

		if (hdr->argsz - minsz < sizeof(flags))
			return -EINVAL;

		flags = __clk_get_flags(vdev->clks[hdr->index].clk);

		ret = copy_to_user((void __user *)arg + minsz, &flags,
				   sizeof(flags)) ? -EFAULT : 0;
		break;
	default:
		ret = -ENXIO;
		break;
	}

	return ret;
}
