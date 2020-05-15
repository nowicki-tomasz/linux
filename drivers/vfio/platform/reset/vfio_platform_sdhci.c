/*
 * VFIO platform driver specialized for AHCI reset
 * reset code is inherited from AHCI native driver
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

#include "../vfio_platform_private.h"

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Tomasz Nowicki <tn@semihalf.com>"
#define DRIVER_DESC     "Reset support for SDHCI vfio platform device"


int vfio_platform_sdhci_reset(struct vfio_platform_device *vdev)
{
	/* Do exactly nothing */
	return 0;
}

module_vfio_reset_handler("marvell,armada-cp110-sdhci", vfio_platform_sdhci_reset);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
