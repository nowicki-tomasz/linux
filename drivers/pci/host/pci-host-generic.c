/*
 * Simple, generic PCI host controller driver targetting firmware-initialised
 * systems and virtual machines (e.g. the PCI emulation provided by kvmtool).
 *
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
 * Copyright (C) 2014 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/platform_device.h>

#include "pci-host-common.h"

static struct pci_ops gen_pci_ops = {
	.map_bus	= gen_pci_map_cfg_bus,
	.read		= pci_generic_config_read,
	.write		= pci_generic_config_write,
};

static const struct of_device_id gen_pci_of_match[] = {
	{ .compatible = "pci-host-cam-generic", .data = (void *)16},
	{ .compatible = "pci-host-ecam-generic", .data = (void *)20},
	{ },
};
MODULE_DEVICE_TABLE(of, gen_pci_of_match);

static int gen_pci_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct of_device_id *of_id;
	struct gen_pci *pci = devm_kzalloc(dev, sizeof(*pci), GFP_KERNEL);

	if (!pci)
		return -ENOMEM;

	of_id = of_match_node(gen_pci_of_match, dev->of_node);
	pci->bus_shift = (unsigned long)of_id->data;
	pci->ops = &gen_pci_ops;

	return pci_host_common_probe(pdev, pci);
}

static struct platform_driver gen_pci_driver = {
	.driver = {
		.name = "pci-host-generic",
		.of_match_table = gen_pci_of_match,
	},
	.probe = gen_pci_probe,
};
module_platform_driver(gen_pci_driver);

MODULE_DESCRIPTION("Generic PCI host driver");
MODULE_AUTHOR("Will Deacon <will.deacon@arm.com>");
MODULE_LICENSE("GPL v2");
