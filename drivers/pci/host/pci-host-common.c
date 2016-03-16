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

void __iomem *gen_pci_map_cfg_bus(struct pci_bus *bus,
					 unsigned int devfn, int where)
{
	struct gen_pci *pci = bus->sysdata;

	return pci_generic_map_bus(pci->cfg, bus->number, devfn, where);
}

static void gen_pci_release_of_pci_ranges(struct gen_pci *pci)
{
	pci_free_resource_list(&pci->resources);
}

static int gen_pci_parse_request_of_pci_ranges(struct gen_pci *pci)
{
	int err, res_valid = 0;
	struct device *dev = pci->host.dev.parent;
	struct device_node *np = dev->of_node;
	resource_size_t iobase;
	struct resource_entry *win;

	err = of_pci_get_host_bridge_resources(np, 0, 0xff, &pci->resources,
					       &iobase);
	if (err)
		return err;

	resource_list_for_each_entry(win, &pci->resources) {
		struct resource *parent, *res = win->res;

		switch (resource_type(res)) {
		case IORESOURCE_IO:
			parent = &ioport_resource;
			err = pci_remap_iospace(res, iobase);
			if (err) {
				dev_warn(dev, "error %d: failed to map resource %pR\n",
					 err, res);
				continue;
			}
			break;
		case IORESOURCE_MEM:
			parent = &iomem_resource;
			res_valid |= !(res->flags & IORESOURCE_PREFETCH);
			break;
		case IORESOURCE_BUS:
			pci->bus_range = res;
		default:
			continue;
		}

		err = devm_request_resource(dev, parent, res);
		if (err)
			goto out_release_res;
	}

	if (!res_valid) {
		dev_err(dev, "non-prefetchable memory resource required\n");
		err = -EINVAL;
		goto out_release_res;
	}

	return 0;

out_release_res:
	gen_pci_release_of_pci_ranges(pci);
	return err;
}

static void gen_pci_generic_unmap_cfg(void *ptr)
{
	pci_generic_unmap_config((struct pci_config_window *)ptr);
}

static int gen_pci_parse_map_cfg_windows(struct gen_pci *pci)
{
	int err;
	struct resource *cfgres = &pci->cfgres;
	struct resource *bus_range = pci->bus_range;
	unsigned int bus_shift = pci->bus_shift;
	struct device *dev = pci->host.dev.parent;
	struct device_node *np = dev->of_node;
	struct pci_config_window *cfg;

	err = of_address_to_resource(np, 0, cfgres);
	if (err) {
		dev_err(dev, "missing \"reg\" property\n");
		return err;
	}

	/* Limit the bus-range to fit within reg */
	bus_range->end = min(bus_range->end,
		bus_range->start + (resource_size(cfgres) >> bus_shift) - 1);

	cfg = pci_generic_map_config(cfgres->start, bus_range->start,
				     bus_range->end, bus_shift, bus_shift - 8);

	if (IS_ERR(cfg))
		return PTR_ERR(cfg);

	err = devm_add_action(dev, gen_pci_generic_unmap_cfg, cfg);
	if (err) {
		gen_pci_generic_unmap_cfg(cfg);
		return err;
	}

	pci->cfg = cfg;
	return 0;
}

int pci_host_common_probe(struct platform_device *pdev,
			  struct gen_pci *pci)
{
	int err;
	const char *type;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct pci_bus *bus, *child;

	type = of_get_property(np, "device_type", NULL);
	if (!type || strcmp(type, "pci")) {
		dev_err(dev, "invalid \"device_type\" %s\n", type);
		return -EINVAL;
	}

	of_pci_check_probe_only();

	pci->host.dev.parent = dev;
	INIT_LIST_HEAD(&pci->host.windows);
	INIT_LIST_HEAD(&pci->resources);

	/* Parse our PCI ranges and request their resources */
	err = gen_pci_parse_request_of_pci_ranges(pci);
	if (err)
		return err;

	/* Parse and map our Configuration Space windows */
	err = gen_pci_parse_map_cfg_windows(pci);
	if (err) {
		gen_pci_release_of_pci_ranges(pci);
		return err;
	}

	/* Do not reassign resources if probe only */
	if (!pci_has_flag(PCI_PROBE_ONLY))
		pci_add_flags(PCI_REASSIGN_ALL_RSRC | PCI_REASSIGN_ALL_BUS);


	bus = pci_scan_root_bus(dev, pci->bus_range->start,
				pci->ops, pci, &pci->resources);
	if (!bus) {
		dev_err(dev, "Scanning rootbus failed");
		return -ENODEV;
	}

	pci_fixup_irqs(pci_common_swizzle, of_irq_parse_and_map_pci);

	if (!pci_has_flag(PCI_PROBE_ONLY)) {
		pci_bus_size_bridges(bus);
		pci_bus_assign_resources(bus);

		list_for_each_entry(child, &bus->children, node)
			pcie_bus_configure_settings(child);
	}

	pci_bus_add_devices(bus);
	return 0;
}

MODULE_DESCRIPTION("Generic PCI host driver common code");
MODULE_AUTHOR("Will Deacon <will.deacon@arm.com>");
MODULE_LICENSE("GPL v2");
