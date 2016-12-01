/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2015 - 2016 Cavium, Inc.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/pci-ecam.h>
#include <linux/platform_device.h>

static const struct of_device_id thunder_pem_of_match[] = {
	{ .compatible = "cavium,pci-host-thunder-pem" },
	{ },
};

static int thunder_pem_probe(struct platform_device *pdev)
{
	return pci_host_common_probe(pdev, &pci_thunder_pem_ops);
}

static struct platform_driver thunder_pem_driver = {
	.driver = {
		.name = KBUILD_MODNAME,
		.of_match_table = thunder_pem_of_match,
	},
	.probe = thunder_pem_probe,
};
builtin_platform_driver(thunder_pem_driver);
