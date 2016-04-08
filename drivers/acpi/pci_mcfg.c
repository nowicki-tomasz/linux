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

#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/pci-acpi.h>
#include <linux/slab.h>

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

/*
 * raw_pci_read/write - raw ACPI PCI config space accessors.
 *
 * By default (__weak) these accessors are empty and should be overwritten
 * by architectures which support operations on ACPI PCI_Config regions.
 */

int __weak raw_pci_read(unsigned int domain, unsigned int bus,
			unsigned int devfn, int reg, int len, u32 *val)
{
	return PCIBIOS_DEVICE_NOT_FOUND;
}

int __weak raw_pci_write(unsigned int domain, unsigned int bus,
			 unsigned int devfn, int reg, int len, u32 val)
{
	return PCIBIOS_DEVICE_NOT_FOUND;
}

/* Call generic map_bus after getting cfg pointer */
static void __iomem *gen_acpi_map_cfg_bus(struct pci_bus *bus,
					  unsigned int devfn, int where)
{
	struct acpi_pci_generic_root_info *ri = bus->sysdata;

	return pci_generic_map_bus(ri->cfg, bus->number, devfn, where);
}

static struct pci_ops acpi_pci_ops = {
	.map_bus	= gen_acpi_map_cfg_bus,
	.read		= pci_generic_config_read,
	.write		= pci_generic_config_write,
};

/* Find the entry in mcfg list which contains range bus_start..bus_end */
static struct mcfg_entry *pci_mcfg_lookup(u16 seg, u8 bus_start, u8 bus_end)
{
	struct mcfg_entry *e;

	list_for_each_entry(e, &pci_mcfg_list, list) {
		if (e->segment == seg &&
		    e->bus_start <= bus_start && bus_start <= e->bus_end &&
		    e->bus_start <= bus_end && bus_end <= e->bus_end)
			return e;
	}

	return NULL;
}

/*
 * init_info - lookup the bus range for the domain in MCFG, and set up
 * config space mapping.
 */
static int pci_acpi_generic_init_info(struct acpi_pci_root_info *ci)
{
	struct acpi_pci_root *root = ci->root;
	struct acpi_pci_generic_root_info *ri = root->sysdata;
	u16 seg = root->segment;
	u8 bus_start = root->secondary.start;
	u8 bus_end = root->secondary.end;
	struct mcfg_entry *e;
	phys_addr_t addr;
	int ret = 0;

	mutex_lock(&pci_mcfg_lock);
	e = pci_mcfg_lookup(seg, bus_start, bus_end);
	if (!e) {
		addr = acpi_pci_root_get_mcfg_addr(root->device->handle);
		if (addr == 0) {
			pr_err(PREFIX"%04x:%02x-%02x bus range error\n",
			       seg, bus_start, bus_end);
			ret = -ENOENT;
			goto err_out;
		}
	} else {
		if (bus_start != e->bus_start) {
			pr_err("%04x:%02x-%02x bus range mismatch %02x\n",
			       seg, bus_start, bus_end, e->bus_start);
			ret = -EINVAL;
			goto err_out;
		} else if (bus_end != e->bus_end) {
			pr_warn("%04x:%02x-%02x bus end mismatch %02x\n",
				seg, bus_start, bus_end, e->bus_end);
			bus_end = min(bus_end, e->bus_end);
		}
		addr = e->addr;
	}

	ri->cfg = pci_generic_map_config(addr, bus_start, bus_end, 20, 12);
	if (IS_ERR(ri->cfg)) {
		ret = PTR_ERR(ri->cfg);
		pr_err(PREFIX"%04x:%02x-%02x error %d mapping CFG\n",
		       seg, bus_start, bus_end, ret);
	}
err_out:
	mutex_unlock(&pci_mcfg_lock);
	return ret;
}

/* release_info: free resrouces allocated by init_info */
static void pci_acpi_generic_release_info(struct acpi_pci_root_info *ci)
{
	struct acpi_pci_generic_root_info *ri = ci->root->sysdata;

	if (ri) {
		if (ri->cfg)
			pci_generic_unmap_config(ri->cfg);
		kfree(ri);
	}
	kfree(ci);
}

static struct acpi_pci_root_ops pci_mcfg_root_ops = {
	.pci_ops = &acpi_pci_ops,
	.init_info = pci_acpi_generic_init_info,
	.release_info = pci_acpi_generic_release_info,
};

struct acpi_pci_root_ops *pci_mcfg_get_init(struct acpi_pci_root *root)
{
	struct acpi_pci_generic_root_info *ri;

	ri = kzalloc(sizeof(*ri), GFP_KERNEL);
	if (!ri)
		return NULL;

	root->sysdata = ri;
	return &pci_mcfg_root_ops;
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
		mutex_lock(&pci_mcfg_lock);
		list_add(&e->list, &pci_mcfg_list);
		mutex_unlock(&pci_mcfg_lock);
		pr_info(PREFIX
			"MMCONFIG for domain %04x [bus %02x-%02x] (base 0x%#lx)\n",
			e->segment, e->bus_start, e->bus_end,
			(unsigned long)e->addr);
	}

	return 0;
}

/* Generic interface called by ACPI - parse and save MCFG table */
void __init pci_mcfg_init(void)
{
	int err = acpi_table_parse(ACPI_SIG_MCFG, pci_mcfg_parse);
	if (err)
		pr_err(PREFIX " Failed to parse MCFG (%d)\n", err);
}
