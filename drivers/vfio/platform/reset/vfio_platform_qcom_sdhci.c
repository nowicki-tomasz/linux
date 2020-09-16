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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/phy/phy.h>
#include <linux/usb/phy.h>

#include "../vfio_platform_private.h"

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Tomasz Nowicki <tn@semihalf.com>"
#define DRIVER_DESC     "Reset support for Qualcomm SDHCI vfio platform device"

int vfio_platform_qcom_sdhci_reset(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct regulator *regulator;

	regulator = devm_regulator_get_optional(dev, "vmmc");
	if (!IS_ERR(regulator)) {
		if (regulator_enable(regulator))
			dev_err(dev,
				"Failed to enable vmmc regulator\n");
	}

	regulator = devm_regulator_get_optional(dev, "vqmmc");
	if (!IS_ERR(regulator)) {
		if (regulator_enable(regulator))
			dev_err(dev,
				"Failed to enable vqmmc regulator\n");
	}

	return 0;
}

module_vfio_reset_handler("qcom,sdhci-msm-v5", vfio_platform_qcom_sdhci_reset);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
