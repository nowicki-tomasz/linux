/*
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

#include <linux/dmi.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/pci-acpi.h>
#include <linux/sfi_acpi.h>
#include <linux/slab.h>

#include "../pci/ecam.h"

#define PREFIX	"ACPI: "

/* Structure to hold entries from the MCFG table */
struct mcfg_entry {
	struct list_head	list;
	phys_addr_t		addr;
	u16			segment;
	u8			bus_start;
	u8			bus_end;
};

/* List to save mcfg entries */
static LIST_HEAD(pci_mcfg_list);
static DEFINE_MUTEX(pci_mcfg_lock);

/* ACPI info for generic ACPI PCI controller */
struct acpi_pci_generic_root_info {
	struct acpi_pci_root_info	common;
	struct pci_config_window	*cfg;	/* config space mapping */
};

/* Find the entry in mcfg list which contains range bus_start */
static struct mcfg_entry *pci_mcfg_lookup(u16 seg, u8 bus_start)
{
	struct mcfg_entry *e;

	list_for_each_entry(e, &pci_mcfg_list, list) {
		if (e->segment == seg &&
		    e->bus_start <= bus_start && bus_start <= e->bus_end)
			return e;
	}

	return NULL;
}

extern struct pci_cfg_fixup __start_acpi_mcfg_fixups[];
extern struct pci_cfg_fixup __end_acpi_mcfg_fixups[];

static struct pci_generic_ecam_ops *pci_acpi_get_ops(struct acpi_pci_root *root)
{
	int bus_num = root->secondary.start;
	int domain = root->segment;
	struct pci_cfg_fixup *f;

	/*
	 * Match against platform specific quirks and return corresponding
	 * CAM ops.
	 *
	 * First match against PCI topology <domain:bus> then use DMI or
	 * custom match handler.
	 */
	for (f = __start_acpi_mcfg_fixups; f < __end_acpi_mcfg_fixups; f++) {
		if ((f->domain == domain || f->domain == PCI_MCFG_DOMAIN_ANY) &&
		    (f->bus_num == bus_num || f->bus_num == PCI_MCFG_BUS_ANY) &&
		    (f->system ? dmi_check_system(f->system) : 1) &&
		    (f->match ? f->match(f, root) : 1))
			return f->ops;
	}
	/* No quirks, use ECAM */
	return &pci_generic_ecam_default_ops;
}

/*
 * Lookup the bus range for the domain in MCFG, and set up config space
 * mapping.
 */
static int pci_acpi_setup_ecam_mapping(struct acpi_pci_root *root,
				       struct acpi_pci_generic_root_info *ri)
{
	u16 seg = root->segment;
	u8 bus_start = root->secondary.start;
	u8 bus_end = root->secondary.end;
	struct pci_config_window *cfg;
	struct mcfg_entry *e;
	phys_addr_t addr;
	int err = 0;

	mutex_lock(&pci_mcfg_lock);
	e = pci_mcfg_lookup(seg, bus_start);
	if (!e) {
		addr = acpi_pci_root_get_mcfg_addr(root->device->handle);
		if (addr == 0) {
			pr_err(PREFIX"%04x:%02x-%02x bus range error\n",
			       seg, bus_start, bus_end);
			err = -ENOENT;
			goto err_out;
		}
	} else {
		if (bus_start != e->bus_start) {
			pr_err("%04x:%02x-%02x bus range mismatch %02x\n",
			       seg, bus_start, bus_end, e->bus_start);
			err = -EINVAL;
			goto err_out;
		} else if (bus_end != e->bus_end) {
			pr_warn("%04x:%02x-%02x bus end mismatch %02x\n",
				seg, bus_start, bus_end, e->bus_end);
			bus_end = min(bus_end, e->bus_end);
		}
		addr = e->addr;
	}

	cfg = pci_generic_ecam_create(&root->device->dev, addr, bus_start,
				      bus_end, pci_acpi_get_ops(root));
	if (IS_ERR(cfg)) {
		err = PTR_ERR(cfg);
		pr_err("%04x:%02x-%02x error %d mapping CAM\n", seg,
			bus_start, bus_end, err);
		goto err_out;
	}

	cfg->domain = seg;
	ri->cfg = cfg;
err_out:
	mutex_unlock(&pci_mcfg_lock);
	return err;
}

/* release_info: free resrouces allocated by init_info */
static void pci_acpi_generic_release_info(struct acpi_pci_root_info *ci)
{
	struct acpi_pci_generic_root_info *ri;

	ri = container_of(ci, struct acpi_pci_generic_root_info, common);
	pci_generic_ecam_free(ri->cfg);
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

/* handle MCFG table entries */
static __init int pci_mcfg_parse(struct acpi_table_header *header)
{
	struct acpi_table_mcfg *mcfg;
	struct acpi_mcfg_allocation *mptr;
	struct mcfg_entry *e, *arr;
	int i, n;

	if (!header)
		return -EINVAL;

	mcfg = (struct acpi_table_mcfg *)header;
	mptr = (struct acpi_mcfg_allocation *) &mcfg[1];
	n = (header->length - sizeof(*mcfg)) / sizeof(*mptr);
	if (n <= 0 || n > 255) {
		pr_err(PREFIX " MCFG has incorrect entries (%d).\n", n);
		return -EINVAL;
	}

	arr = kcalloc(n, sizeof(*arr), GFP_KERNEL);
	if (!arr)
		return -ENOMEM;

	for (i = 0, e = arr; i < n; i++, mptr++, e++) {
		e->segment = mptr->pci_segment;
		e->addr =  mptr->address;
		e->bus_start = mptr->start_bus_number;
		e->bus_end = mptr->end_bus_number;
		list_add(&e->list, &pci_mcfg_list);
		pr_info(PREFIX
			"MCFG entry for domain %04x [bus %02x-%02x] (base %pa)\n",
			e->segment, e->bus_start, e->bus_end, &e->addr);
	}

	return 0;
}

/* Interface called by ACPI - parse and save MCFG table */
void __init pci_mcfg_init(void)
{
	int err = acpi_table_parse(ACPI_SIG_MCFG, pci_mcfg_parse);
	if (err)
		pr_err(PREFIX "Failed to parse MCFG (%d)\n", err);
	else if (list_empty(&pci_mcfg_list))
		pr_info(PREFIX "No valid entries in MCFG table.\n");
	else {
		struct mcfg_entry *e;
		int i = 0;
		list_for_each_entry(e, &pci_mcfg_list, list)
			i++;
		pr_info(PREFIX "MCFG table loaded, %d entries\n", i);
	}
}

/* Raw operations, works only for MCFG entries with an associated bus */
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
