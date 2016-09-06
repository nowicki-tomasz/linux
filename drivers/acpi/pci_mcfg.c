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
struct mcfg_fixup {
	char oem_id[ACPI_OEM_ID_SIZE + 1];
	char oem_table_id[ACPI_OEM_TABLE_ID_SIZE + 1];
	u32 oem_revision;
	struct resource domain_range;
	struct resource bus_range;
	struct pci_ecam_ops *ops;
	struct resource res;
};

#define MCFG_DOM_RANGE(start, end)	DEFINE_RES_NAMED((start),	\
						((end) - (start) + 1), NULL, 0)
#define MCFG_DOM_ANY			MCFG_DOM_RANGE(0x0, 0xffff)
#define MCFG_BUS_RANGE(start, end)	DEFINE_RES_NAMED((start),	\
						((end) - (start) + 1),	\
						NULL, IORESOURCE_BUS)
#define MCFG_BUS_ANY			MCFG_BUS_RANGE(0x0, 0xff)

static struct mcfg_fixup mcfg_quirks[] = {
/*	{ OEM_ID, OEM_TABLE_ID, REV, DOMAIN, BUS_RANGE, pci_ops, init_hook }, */
#ifdef CONFIG_PCI_HOST_THUNDER_PEM
	/* Pass2.0 */
	{ "CAVIUM", "THUNDERX", 1, MCFG_DOM_RANGE(4, 9), MCFG_BUS_ANY, NULL,
	  thunder_pem_cfg_init },
	{ "CAVIUM", "THUNDERX", 1, MCFG_DOM_RANGE(14, 19), MCFG_BUS_ANY, NULL,
	  thunder_pem_cfg_init },
#endif
};

static bool pci_mcfg_fixup_match(struct mcfg_fixup *f,
				 struct acpi_table_header *mcfg_header)
{
	return (!memcmp(f->oem_id, mcfg_header->oem_id, ACPI_OEM_ID_SIZE) &&
		!memcmp(f->oem_table_id, mcfg_header->oem_table_id,
			ACPI_OEM_TABLE_ID_SIZE) &&
		f->oem_revision == mcfg_header->oem_revision);
}

static acpi_status pci_mcfg_match_quirks(struct acpi_pci_root *root,
				 struct resource *cfgres,
				 struct pci_ecam_ops **ecam_ops)
{
	struct resource dom_res = MCFG_DOM_RANGE(root->segment, root->segment);
	struct resource *bus_res = &root->secondary;
	struct mcfg_fixup *f = mcfg_quirks;
	struct acpi_table_header *mcfg_header;
	acpi_status status;
	int i;

	status = acpi_get_table(ACPI_SIG_MCFG, 0, &mcfg_header);
	if (ACPI_FAILURE(status))
		return status;

	/*
	 * First match against PCI topology <domain:bus> then use OEM ID, OEM
	 * table ID, and OEM revision from MCFG table standard header.
	 */
	for (i = 0; i < ARRAY_SIZE(mcfg_quirks); i++, f++) {
		if (resource_contains(&f->domain_range, &dom_res) &&
		    resource_contains(&f->bus_range, bus_res) &&
		    pci_mcfg_fixup_match(f, mcfg_header)) {
			dev_info(&root->device->dev, "Applying PCI MCFG quirks for %s %s rev: %d\n",
				 f->oem_id, f->oem_table_id, f->oem_revision);
			*cfgres = f->res;
			*ecam_ops =  f->ops;
			return AE_OK;
		}
	}
	return AE_NOT_FOUND;
}

/* List to save MCFG entries */
static LIST_HEAD(pci_mcfg_list);

static int pci_mcfg_lookup(struct acpi_pci_root *root,
			   struct resource *cfgres,
			   struct pci_ecam_ops **ecam_ops)
{
	struct resource *bus_res = &root->secondary;
	u16 seg = root->segment;
	struct pci_ecam_ops *ops;
	struct mcfg_entry *e;
	struct resource res;
	acpi_status status;

	/* Use address from _CBA if present, otherwise lookup MCFG */
	if (root->mcfg_addr)
		goto skip_lookup;

	/*
	 * We expect exact match, unless MCFG entry end bus covers more than
	 * specified by caller.
	 */
	list_for_each_entry(e, &pci_mcfg_list, list) {
		if (e->segment == seg && e->bus_start == bus_res->start &&
		    e->bus_end >= bus_res->end) {
			root->mcfg_addr = e->addr;
		}

	}
skip_lookup:

	memset(&res, 0, sizeof(res));
	if (root->mcfg_addr) {
		res.start = root->mcfg_addr + (bus_res->start << 20);
		res.end = res.start + (resource_size(bus_res) << 20) - 1;
		res.flags = IORESOURCE_MEM;
	}

	ops = &pci_generic_ecam_ops;
	/*
	 * Let to override CFG resource and ops, however no MCFG entry nor
	 * related quirk means something went wrong.
	 */
	status = pci_mcfg_match_quirks(root, &res, ops);
	if (!root->mcfg_addr && status == AE_NOT_FOUND) {
		return -ENXIO;

	*cfgres = res;
	*ecam_ops = ops;

	return 0;
}

/*
 * Lookup the bus range for the domain in MCFG, and set up config space
 * mapping.
 */
struct pci_config_window *
pci_acpi_setup_ecam_mapping(struct acpi_pci_root *root)
{
	struct resource *bus_res = &root->secondary;
	u16 seg = root->segment;
	struct pci_config_window *cfg;
	struct resource cfgres;
	struct pci_ecam_ops *ecam_ops;
	int ret;

	ret = pci_mcfg_lookup(root, &cfgres, &ecam_ops);
	if (ret) {
		dev_err(&root->device->dev, "%04x:%pR ECAM region not found\n",
			seg, bus_res);
		return ret;
	}

	cfg = pci_ecam_create(&root->device->dev, &cfgres, bus_res, ecam_ops);
	if (IS_ERR(cfg)) {
		dev_err(&root->device->dev, "%04x:%pR error %ld mapping ECAM\n",
			seg, bus_res, PTR_ERR(cfg));
		return NULL;
	}

	return cfg;
}

static int pci_mcfg_parse(struct acpi_table_header *header)
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
void pci_mmcfg_late_init(void)
{
	int err = acpi_table_parse(ACPI_SIG_MCFG, pci_mcfg_parse);
	if (err)
		pr_err("Failed to parse MCFG (%d)\n", err);
}
