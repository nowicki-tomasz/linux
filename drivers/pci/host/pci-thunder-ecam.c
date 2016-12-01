/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2015, 2016 Cavium, Inc.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/pci-ecam.h>
#include <linux/platform_device.h>

static const struct of_device_id thunder_ecam_of_match[] = {
	{ .compatible = "cavium,pci-host-thunder-ecam" },
	{ },
};

static int thunder_ecam_probe(struct platform_device *pdev)
{
	return pci_host_common_probe(pdev, &pci_thunder_ecam_ops);
}

static struct platform_driver thunder_ecam_driver = {
	.driver = {
		.name = KBUILD_MODNAME,
		.of_match_table = thunder_ecam_of_match,
	},
	.probe = thunder_ecam_probe,
};
builtin_platform_driver(thunder_ecam_driver);
