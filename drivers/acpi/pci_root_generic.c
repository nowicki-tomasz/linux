/*
 * Copyright (C) 2016 Broadcom
 *	Author: Jayachandran C <jchandra@broadcom.com>
 * Copyright (C) 2016 Semihalf
 * 	Author: Tomasz Nowicki <tn@semihalf.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation (the "GPL").
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 (GPLv2) for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 (GPLv2) along with this source code.
 */
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/pci-acpi.h>
#include <linux/slab.h>

#include "../pci/ecam.h"

#define PREFIX	"ACPI PCI: "

/* ACPI info for generic ACPI PCI controller */
struct acpi_pci_generic_root_info {
	struct acpi_pci_root_info	common;
	struct pci_config_window	*cfg;	/* config space mapping */
};

void acpi_pci_set_companion(struct pci_host_bridge *bridge)
{
	struct pci_config_window *cfg = bridge->bus->sysdata;

	ACPI_COMPANION_SET(&bridge->dev, cfg->companion);
}

int acpi_pci_bus_domain_nr(struct pci_bus *bus)
{
	struct pci_config_window *cfg = bus->sysdata;

	return cfg->domain;
}

/*
 * Lookup the bus range for the domain in MCFG, and set up config space
 * mapping.
 */
static int pci_acpi_setup_ecam_mapping(struct acpi_pci_root *root,
				       struct acpi_pci_generic_root_info *ri)
{
	struct resource *bus_res = &root->secondary;
	u16 seg = root->segment;
	struct pci_config_window *cfg;
	struct resource cfgres;
	unsigned int bsz;
	phys_addr_t addr;

	addr = pci_mcfg_lookup(root->device, seg, bus_res);
	if (IS_ERR_VALUE(addr)) {
		pr_err(PREFIX"%04x:%pR MCFG region not found\n", seg, bus_res);
		return addr;
	}

	bsz = 1 << pci_generic_ecam_ops.bus_shift;
	cfgres.start = addr + bus_res->start * bsz;
	cfgres.end = addr + (bus_res->end + 1) * bsz - 1;
	cfgres.flags = IORESOURCE_MEM;
	cfg = pci_ecam_create(&root->device->dev, &cfgres, bus_res,
						  &pci_generic_ecam_ops);
	if (IS_ERR(cfg)) {
		pr_err("%04x:%pR error %ld mapping CAM\n", seg, bus_res,
		       PTR_ERR(cfg));
		return PTR_ERR(cfg);
	}

	cfg->domain = seg;
	cfg->companion = root->device;
	ri->cfg = cfg;
	return 0;
}

/* release_info: free resrouces allocated by init_info */
static void pci_acpi_generic_release_info(struct acpi_pci_root_info *ci)
{
	struct acpi_pci_generic_root_info *ri;

	ri = container_of(ci, struct acpi_pci_generic_root_info, common);
	pci_ecam_free(ri->cfg);
	kfree(ri);
}

static struct acpi_pci_root_ops acpi_pci_root_ops = {
	.release_info = pci_acpi_generic_release_info,
};

/* Interface called from ACPI code to setup PCI host controller */
struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
{
	int node = acpi_get_node(root->device->handle);
	struct acpi_pci_generic_root_info *ri;
	struct pci_bus *bus, *child;
	int err;

	ri = kzalloc_node(sizeof(*ri), GFP_KERNEL, node);
	if (!ri)
		return NULL;

	err = pci_acpi_setup_ecam_mapping(root, ri);
	if (err)
		return NULL;

	acpi_pci_root_ops.pci_ops = &ri->cfg->ops->pci_ops;
	bus = acpi_pci_root_create(root, &acpi_pci_root_ops, &ri->common,
				   ri->cfg);
	if (!bus)
		return NULL;

	pci_bus_size_bridges(bus);
	pci_bus_assign_resources(bus);

	list_for_each_entry(child, &bus->children, node)
		pcie_bus_configure_settings(child);

	return bus;
}

int raw_pci_read(unsigned int domain, unsigned int busn, unsigned int devfn,
		 int reg, int len, u32 *val)
{
	struct pci_bus *bus = pci_find_bus(domain, busn);

	if (!bus)
		return PCIBIOS_DEVICE_NOT_FOUND;
	return bus->ops->read(bus, devfn, reg, len, val);
}

int raw_pci_write(unsigned int domain, unsigned int busn, unsigned int devfn,
		  int reg, int len, u32 val)
{
	struct pci_bus *bus = pci_find_bus(domain, busn);

	if (!bus)
		return PCIBIOS_DEVICE_NOT_FOUND;
	return bus->ops->write(bus, devfn, reg, len, val);
}
