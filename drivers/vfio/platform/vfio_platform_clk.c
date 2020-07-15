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
