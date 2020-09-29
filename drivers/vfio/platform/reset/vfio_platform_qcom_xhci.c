/*
 * VFIO platform driver specialized for XHCI reset
 * reset code is inherited from XHCI native driver
 *
 * Copyright 2016 Marvell Semiconductors, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/device.h>
#include <linux/phy/phy.h>
#include <linux/reset.h>
#include <linux/delay.h>

#include "../vfio_platform_private.h"

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Tomasz Nowicki <tn@semihalf.com>"
#define DRIVER_DESC     "Reset support for Qualcomm XHCI vfio platform device"

#define MAX_XHCI_PHYS		2

int vfio_platform_dwc3_xhci_reset(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct device_node *np = dev->of_node, *dwc3_np;
	struct reset_control *resets;
	int ret;

	resets = devm_reset_control_array_get_optional_exclusive(dev);
	if (IS_ERR(resets)) {
		ret = PTR_ERR(resets);
		dev_err(dev, "failed to get resets, err=%d\n", ret);
		goto reset_out;
	}

	ret = reset_control_assert(resets);
	if (ret) {
		dev_err(dev, "failed to assert resets, err=%d\n", ret);
		goto reset_out;
	}

	usleep_range(10, 1000);

	ret = reset_control_deassert(resets);
	if (ret) {
		dev_err(dev, "failed to deassert resets, err=%d\n", ret);
	}

reset_out:

	dwc3_np = of_get_child_by_name(np, "dwc3");
	if (!dwc3_np) {
		dev_err(dev, "failed to find dwc3 core child\n");
		return -ENODEV;
	}

	ret = of_platform_populate(np, NULL, NULL, dev);
	if (ret) {
		dev_err(dev, "failed to register dwc3 core - %d\n", ret);
		return ret;
	}

	return 0;
}

module_vfio_reset_handler("qcom,sc7180-dwc3", vfio_platform_dwc3_xhci_reset);

int vfio_platform_qcom_xhci_reset(struct vfio_platform_device *vdev)
{
	return 0;
}

module_vfio_reset_handler("snps,dwc3", vfio_platform_qcom_xhci_reset);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
