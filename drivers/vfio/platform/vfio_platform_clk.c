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
	return 0;
}

void vfio_platform_clk_cleanup(struct vfio_platform_device *vdev)
{
}
