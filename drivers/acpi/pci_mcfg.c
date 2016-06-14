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

#define pr_fmt(fmt) "ACPI: " fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/pci-acpi.h>
#include <linux/pci-ecam.h>

/* Structure to hold entries from the MCFG table */
struct mcfg_entry {
	struct list_head	list;
	phys_addr_t		addr;
	u16			segment;
	u8			bus_start;
	u8			bus_end;
};

/* List to save MCFG entries */
static LIST_HEAD(pci_mcfg_list);

extern struct pci_cfg_fixup __start_acpi_mcfg_fixups[];
extern struct pci_cfg_fixup __end_acpi_mcfg_fixups[];

struct pci_ecam_ops *pci_mcfg_get_ops(int domain, int bus_num)
{
	struct pci_cfg_fixup *f;
	struct acpi_table_header *mcfg_header;
	struct acpi_table_mcfg *mcfg_table;
	acpi_status status;

	status = acpi_get_table(ACPI_SIG_MCFG, 0, &mcfg_header);
	if (ACPI_FAILURE(status))
		return &pci_generic_ecam_ops;

	/*
	 * Match against platform specific quirks and return corresponding
	 * CAM ops.
	 *
	 * First match against PCI topology <domain:bus> then use OEM ID and
	 * OEM revision from MCFG table standard header.
	 */
	mcfg_table = (struct acpi_table_mcfg *)mcfg_header;
	for (f = __start_acpi_mcfg_fixups; f < __end_acpi_mcfg_fixups; f++) {
		if ((f->domain == domain || f->domain == PCI_MCFG_DOMAIN_ANY) &&
		    (f->bus_num == bus_num || f->bus_num == PCI_MCFG_BUS_ANY) &&
		    (!strncmp(f->oem_id, mcfg_table->header.oem_id,
			      ACPI_OEM_ID_SIZE)) &&
		    (!strncmp(f->oem_table_id, mcfg_table->header.oem_table_id,
			      min_t(size_t, strlen(f->oem_id),
				    ACPI_OEM_TABLE_ID_SIZE))) &&
		    (f->oem_revision == mcfg_table->header.oem_revision))
			return f->ops;
	}
	/* No quirks, use ECAM */
	return &pci_generic_ecam_ops;
}

phys_addr_t pci_mcfg_lookup(u16 seg, struct resource *bus_res)
{
	struct mcfg_entry *e;

	/*
	 * We expect exact match, unless MCFG entry end bus covers more than
	 * specified by caller.
	 */
	list_for_each_entry(e, &pci_mcfg_list, list) {
		if (e->segment == seg && e->bus_start == bus_res->start &&
		    e->bus_end >= bus_res->end)
			return e->addr;
	}

	return 0;
}

static __init int pci_mcfg_parse(struct acpi_table_header *header)
{
	struct acpi_table_mcfg *mcfg;
	struct acpi_mcfg_allocation *mptr;
	struct mcfg_entry *e, *arr;
	int i, n;

	if (header->length < sizeof(struct acpi_table_mcfg))
		return -EINVAL;

	n = (header->length - sizeof(struct acpi_table_mcfg)) /
					sizeof(struct acpi_mcfg_allocation);
	mcfg = (struct acpi_table_mcfg *)header;
	mptr = (struct acpi_mcfg_allocation *) &mcfg[1];

	arr = kcalloc(n, sizeof(*arr), GFP_KERNEL);
	if (!arr)
		return -ENOMEM;

	for (i = 0, e = arr; i < n; i++, mptr++, e++) {
		e->segment = mptr->pci_segment;
		e->addr =  mptr->address;
		e->bus_start = mptr->start_bus_number;
		e->bus_end = mptr->end_bus_number;
		list_add(&e->list, &pci_mcfg_list);
	}

	pr_info("MCFG table detected, %d entries\n", n);
	return 0;
}

/* Interface called by ACPI - parse and save MCFG table */
void __init pci_mmcfg_late_init(void)
{
	int err = acpi_table_parse(ACPI_SIG_MCFG, pci_mcfg_parse);
	if (err)
		pr_err("Failed to parse MCFG (%d)\n", err);
}
