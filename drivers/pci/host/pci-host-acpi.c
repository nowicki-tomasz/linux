/*
 * ACPI based generic PCI host controller driver
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
 * Copyright (C) 2015 Semihalf
 * Author: Tomasz Nowicki <tn@semihalf.com>
 */

#include <linux/acpi.h>
#include <linux/ecam.h>
#include <linux/of_address.h>
#include <linux/pci.h>
#include <linux/pci-acpi.h>

static int pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	if (pci_dev_msi_enabled(dev))
		return 0;

	return acpi_pci_irq_enable(dev);
}

int pcibios_root_bridge_prepare(struct pci_host_bridge *bridge)
{
	bridge->map_irq = pcibios_map_irq;
	return 0;
}

static void pci_mcfg_release_info(struct acpi_pci_root_info *ci)
{
	pci_mmcfg_teardown_map(ci);
	kfree(ci);
}

static int pci_acpi_root_prepare_resources(struct acpi_pci_root_info *ci)
{
	struct resource_entry *entry, *tmp;
	int ret;

	ret = acpi_pci_probe_root_resources(ci);
	if (ret <= 0)
		return ret;

	resource_list_for_each_entry_safe(entry, tmp, &ci->resources) {
		struct resource *res = entry->res;

		/*
		 * TODO: need to move pci_register_io_range() function out
		 * of drivers/of/address.c for both used by DT and ACPI
		 */
		if (res->flags & IORESOURCE_IO) {
			resource_size_t cpu_addr = res->start + entry->offset;
			resource_size_t pci_addr = res->start;
			resource_size_t length = res->end - res->start;
			unsigned long port;
			int err;

			err = pci_register_io_range(cpu_addr, length);
			if (err) {
				resource_list_destroy_entry(entry);
				continue;
			}

			port = pci_address_to_pio(cpu_addr);
			if (port == (unsigned long)-1) {
				resource_list_destroy_entry(entry);
				continue;
			}

			res->start = port;
			res->end = port + length;
			entry->offset = port - pci_addr;

			if (pci_remap_iospace(res, cpu_addr) < 0)
				resource_list_destroy_entry(entry);
		}
	}

	return ret;
}

static struct acpi_pci_root_ops acpi_pci_root_ops = {
	.init_info = pci_mmcfg_setup_map,
	.release_info = pci_mcfg_release_info,
	.prepare_resources = pci_acpi_root_prepare_resources,
};

/* Root bridge scanning */
struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
{
	int node = acpi_get_node(root->device->handle);
	int domain = root->segment;
	int busnum = root->secondary.start;
	struct acpi_pci_root_info *info;
	struct pci_bus *bus;

	if (domain && !pci_domains_supported) {
		pr_warn("PCI %04x:%02x: multiple domains not supported.\n",
			domain, busnum);
		return NULL;
	}

	info = kzalloc_node(sizeof(*info), GFP_KERNEL, node);
	if (!info) {
		dev_err(&root->device->dev,
			"pci_bus %04x:%02x: ignored (out of memory)\n",
			domain, busnum);
		return NULL;
	}

	acpi_pci_root_ops.pci_ops = pci_mcfg_get_ops(domain, busnum);
	bus = acpi_pci_root_create(root, &acpi_pci_root_ops, info, root);

	/* After the PCI-E bus has been walked and all devices discovered,
	 * configure any settings of the fabric that might be necessary.
	 */
	if (bus) {
		struct pci_bus *child;
		pci_bus_size_bridges(bus);
		pci_bus_assign_resources(bus);

		list_for_each_entry(child, &bus->children, node)
			pcie_bus_configure_settings(child);
	}

	return bus;
}
