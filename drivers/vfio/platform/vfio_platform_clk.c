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
	struct clk_devres *clk_res = &vdev->clk_res;
	int ret;

	ret = devm_clk_bulk_get_all(dev, &clk_res->clk_bulk);
	if (ret < 0) {
		dev_err(dev, "failed to get clocks %d\n", ret);
		return ret;
	}
	clk_res->num_clks = ret;

	if (!clk_res->num_clks)
		return 0;

	clk_res->vdev = devm_kcalloc(dev, clk_res->num_clks,
				     sizeof(clk_res->vdev), GFP_KERNEL);
	if (!clk_res->vdev)
		return -ENOMEM;

	return 0;
}

static int vfio_platform_clk_add(struct vfio_platform_device *vdev,
				 struct vhost_dev *vhost, int index)
{
	struct clk_devres *clk_res = &vdev->clk_res;

	clk_res->vdev[index] = vhost;
	return 0;
}

static int vfio_platform_clk_del(struct vfio_platform_device *vdev,
				 struct vhost_dev *vhost, int index)
{
	struct clk_devres *clk_res = &vdev->clk_res;

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
}
