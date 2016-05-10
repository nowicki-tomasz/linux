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

#define PREFIX	"ACPI: "

/* Root pointer to the mapped MCFG table */
static struct acpi_table_mcfg *mcfg_table;

#define MCFG_ENTRIES(mcfg_ptr)	(((mcfg_ptr)->header.length -		\
				sizeof(struct acpi_table_mcfg)) /	\
				sizeof(struct acpi_mcfg_allocation))

static phys_addr_t pci_mcfg_lookup_static(u16 seg, u8 bus_start, u8 bus_end)
{
	struct acpi_mcfg_allocation *mptr;
	int i;

	if (!mcfg_table) {
		pr_err(PREFIX "MCFG table not available, lookup failed\n");
		return -ENXIO;
	}

	mptr = (struct acpi_mcfg_allocation *) &mcfg_table[1];

	/*
	 * We expect exact match, unless MCFG entry end bus covers more than
	 * specified by caller.
	 */
	for (i = 0; i < MCFG_ENTRIES(mcfg_table); i++, mptr++) {
		if (mptr->pci_segment == seg &&
		    mptr->start_bus_number == bus_start &&
		    mptr->end_bus_number >= bus_end) {
			return mptr->address;
		}
	}

	return -ENXIO;
}

phys_addr_t pci_mcfg_lookup(struct acpi_device *device, u16 seg,
			    struct resource *bus_res)
{
	phys_addr_t addr;

	addr = acpi_pci_root_get_mcfg_addr(device->handle);
	if (addr)
		return addr;

	return pci_mcfg_lookup_static(seg, bus_res->start, bus_res->end);
}

static __init int pci_mcfg_parse(struct acpi_table_header *header)
{
	struct acpi_table_mcfg *mcfg;
	int n;

	if (!header)
		return -EINVAL;

	mcfg = (struct acpi_table_mcfg *)header;
	n = MCFG_ENTRIES(mcfg);
	if (n <= 0 || n > 255) {
		pr_err(PREFIX "MCFG has incorrect entries (%d).\n", n);
		return -EINVAL;
	}

	mcfg_table = mcfg;
	pr_info(PREFIX "MCFG table loaded, %d entries detected\n", n);
	return 0;
}

/* Interface called by ACPI - parse and save MCFG table */
void __init pci_mmcfg_late_init(void)
{
	int err = acpi_table_parse(ACPI_SIG_MCFG, pci_mcfg_parse);
	if (err)
		pr_err(PREFIX "Failed to parse MCFG (%d)\n", err);
}
