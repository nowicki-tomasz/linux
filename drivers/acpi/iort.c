/*
 * Copyright (C) 2015, Linaro Ltd.
 *	Author: Tomasz Nowicki <tomasz.nowicki@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * This file implements early detection/parsing of I/O mapping
 * reported to OS through firmware via I/O Remapping Table (IORT)
 * IORT document number: ARM DEN 0049A
 */

#define pr_fmt(fmt)	"ACPI: IORT: " fmt

#include <linux/export.h>
#include <linux/iort.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/pci.h>

struct iort_its_msi_chip {
	struct list_head	list;
	struct fwnode_handle	*fw_node;
	u32			translation_id;
};

typedef acpi_status (*iort_find_node_callback)
	(struct acpi_iort_node *node, void *context);

/* Root pointer to the mapped IORT table */
static struct acpi_table_header *iort_table;

static LIST_HEAD(iort_msi_chip_list);

/**
 * iort_register_domain_token() - register domain token and related ITS ID
 * 				  to the list from where we can get it back
 * 				  later on.
 * @translation_id: ITS ID
 * @token: domain token
 *
 * Returns: 0 on success, -ENOMEM if not memory when allocating list element.
 */
int iort_register_domain_token(int trans_id, struct fwnode_handle *fw_node)
{
	struct iort_its_msi_chip *its_msi_chip;

	its_msi_chip = kzalloc(sizeof(*its_msi_chip), GFP_KERNEL);
	if (!its_msi_chip)
		return -ENOMEM;

	its_msi_chip->fw_node = fw_node;
	its_msi_chip->translation_id = trans_id;

	list_add(&its_msi_chip->list, &iort_msi_chip_list);
	return 0;
}

/**
 * iort_find_its_domain_token() - find domain token based on given ITS ID.
 * @translation_id: ITS ID
 *
 * Returns: domain token when find on the list, NULL otherwise.
 */
struct fwnode_handle *iort_find_its_domain_token(int trans_id)
{
	struct iort_its_msi_chip *its_msi_chip;

	list_for_each_entry(its_msi_chip, &iort_msi_chip_list, list) {
		if (its_msi_chip->translation_id == trans_id)
			return its_msi_chip->fw_node;
	}

	return NULL;
}

static struct acpi_iort_node *
iort_scan_node(enum acpi_iort_node_type type,
	       iort_find_node_callback callback, void *context)
{
	struct acpi_iort_node *iort_node, *iort_end;
	struct acpi_table_iort *iort;
	int i;

	if (!iort_table)
		return NULL;

	/*
	 * iort_table and iort both point to the start of IORT table, but
	 * have different struct types
	 */
	iort = (struct acpi_table_iort *)iort_table;

	/* Get the first IORT node */
	iort_node = ACPI_ADD_PTR(struct acpi_iort_node, iort,
				 iort->node_offset);
	iort_end = ACPI_ADD_PTR(struct acpi_iort_node, iort_table,
				iort_table->length);

	for (i = 0; i < iort->node_count; i++) {
		if (iort_node >= iort_end) {
			pr_err("iort node pointer overflows, bad table\n");
			return NULL;
		}

		if (iort_node->type == type) {
			if (ACPI_SUCCESS(callback(iort_node, context)))
				return iort_node;
		}

		iort_node = ACPI_ADD_PTR(struct acpi_iort_node, iort_node,
					 iort_node->length);
	}

	return NULL;
}

static struct acpi_iort_node *iort_find_parent_node(struct acpi_iort_node *node)
{
	struct acpi_iort_id_mapping *id;

	if (!node || !node->mapping_offset || !node->mapping_count)
		return NULL;

	id = ACPI_ADD_PTR(struct acpi_iort_id_mapping, node,
			      node->mapping_offset);
	/* Firmware bug! */
	if (!id->output_reference) {
		pr_err(FW_BUG "[node %p type %d] ID map has NULL parent reference\n",
		       node, node->type);
		return NULL;
	}

	node = ACPI_ADD_PTR(struct acpi_iort_node, iort_table,
			    id->output_reference);
	return node;
}

static acpi_status
iort_find_dev_callback(struct acpi_iort_node *node, void *context)
{
	struct acpi_iort_root_complex *pci_rc;
	struct device *dev = context;
	struct pci_bus *bus;

	switch (node->type) {
	case ACPI_IORT_NODE_PCI_ROOT_COMPLEX:
		bus = to_pci_bus(dev);
		pci_rc = (struct acpi_iort_root_complex *)node->node_data;

		/*
		 * It is assumed that PCI segment numbers have a one-to-one
		 * mapping with root complexes. Each segment number can
		 * represent only one root complex.
		 */
		if (pci_rc->pci_segment_number == pci_domain_nr(bus))
			return AE_OK;

		break;
	}

	return AE_NOT_FOUND;
}

/**
 * iort_pci_find_its_id() - find the ITS identifier based on specified device.
 * @dev: device
 * @idx: index of the ITS identifier list
 * @its_id: ITS identifier
 *
 * Returns: 0 on success, appropriate error value otherwise
 */
static int
iort_pci_find_its_id(struct device *dev, unsigned int idx, int *its_id)
{
	struct acpi_iort_its_group *its;
	struct acpi_iort_node *node;

	node = iort_scan_node(ACPI_IORT_NODE_PCI_ROOT_COMPLEX,
			      iort_find_dev_callback, dev);
	if (!node) {
		pr_err("can't find node related to %s device\n", dev_name(dev));
		return -ENXIO;
	}

	/* Go upstream until find its parent ITS node */
	while (node->type != ACPI_IORT_NODE_ITS_GROUP) {
		node = iort_find_parent_node(node);
		if (!node)
			return -ENXIO;
	}

	/* Move to ITS specific data */
	its = (struct acpi_iort_its_group *)node->node_data;
	if (idx > its->its_count) {
		pr_err("requested ITS ID index [%d] is greater than available ITS count [%d]\n",
		       idx, its->its_count);
		return -ENXIO;
	}

	*its_id = its->identifiers[idx];
	return 0;
}


/**
 * iort_find_pci_domain_token() - find registered domain token related to
 * 				  PCI device
 * @dev: device
 *
 * Returns: domain token on success, NULL otherwise
 */
struct fwnode_handle *iort_find_pci_domain_token(struct device *dev)
{
	static struct fwnode_handle *domain_handle;
	int its_id;

	if (iort_pci_find_its_id(dev, 0, &its_id))
		return NULL;

	domain_handle = iort_find_its_domain_token(its_id);
	if (!domain_handle)
		return NULL;

	return domain_handle;
}

static int
iort_translate_dev_to_devid(struct acpi_iort_node *node, u32 req_id,
			    u32 *dev_id)
{
	u32 curr_id = req_id;

	if (!node)
		return -EINVAL;

	/* Go upstream */
	while (node->type != ACPI_IORT_NODE_ITS_GROUP) {
		struct acpi_iort_id_mapping *id;
		int i, found = 0;

		/* Exit when no mapping array */
		if (!node->mapping_offset || !node->mapping_count)
			return -EINVAL;

		id = ACPI_ADD_PTR(struct acpi_iort_id_mapping, node,
				  node->mapping_offset);

		for (i = 0, found = 0; i < node->mapping_count; i++, id++) {
			/*
			 * Single mapping is not translation rule,
			 * lets move on for this case
			 */
			if (id->flags & ACPI_IORT_ID_SINGLE_MAPPING)
				continue;

			if (curr_id < id->input_base ||
			    (curr_id > id->input_base + id->id_count))
				continue;

			curr_id = id->output_base + (curr_id - id->input_base);
			found = 1;
			break;
		}

		if (!found)
			return -ENXIO;

		node = iort_find_parent_node(node);
		if (!node)
			return -ENXIO;
	}

	*dev_id = curr_id;
	return 0;
}

/**
 * iort_find_pci_id() - find PCI device ID based on requester ID
 * @dev: device
 * @req_id: requester ID
 * @dev_id: device ID
 *
 * Returns: 0 on success, appropriate error value otherwise
 */
int iort_find_pci_id(struct pci_dev *pdev, u32 req_id, u32 *dev_id)
{
	struct pci_bus *bus = pdev->bus;
	struct acpi_iort_node *node;
	int err;

	node = iort_scan_node(ACPI_IORT_NODE_PCI_ROOT_COMPLEX,
			      iort_find_dev_callback, &bus->dev);
	if (!node) {
		pr_err("can't find node related to %s device\n",
		       dev_name(&pdev->dev));
		return -ENXIO;
	}

	err = iort_translate_dev_to_devid(node, req_id, dev_id);
	return err;
}

static int __init iort_table_detect(void)
{
	acpi_status status;

	if (acpi_disabled)
		return -ENODEV;

	status = acpi_get_table(ACPI_SIG_IORT, 0, &iort_table);
	if (ACPI_FAILURE(status)) {
		const char *msg = acpi_format_exception(status);
		pr_err("Failed to get table, %s\n", msg);
		return -EINVAL;
	}

	return 0;
}
arch_initcall(iort_table_detect);
