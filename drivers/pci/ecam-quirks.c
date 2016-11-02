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
 *
 * This file contains PCI configuration accessors for not fully ECAM compliant
 * platforms.
 */

#include <linux/pci-acpi.h>
#include <linux/pci-ecam.h>

/* ECAM ops for 32-bit access only (non-compliant) */
struct pci_ecam_ops pci_32b_ops = {
	.bus_shift	= 20,
	.pci_ops	= {
		.map_bus	= pci_ecam_map_bus,
		.read		= pci_generic_config_read32,
		.write		= pci_generic_config_write32,
	}
};
