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

#include <linux/init.h>
#include <linux/pci.h>

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
