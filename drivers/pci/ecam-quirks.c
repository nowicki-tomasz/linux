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

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/pci-acpi.h>
#include <linux/pci-ecam.h>
#include <linux/platform_device.h>
#include "pci.h"

/* ECAM ops for 32-bit access only (non-compliant) */
struct pci_ecam_ops pci_32b_ops = {
	.bus_shift	= 20,
	.pci_ops	= {
		.map_bus	= pci_ecam_map_bus,
		.read		= pci_generic_config_read32,
		.write		= pci_generic_config_write32,
	}
};

#ifdef CONFIG_ACPI
static int hisi_pcie_acpi_rd_conf(struct pci_bus *bus, u32 devfn, int where,
				  int size, u32 *val)
{
	struct pci_config_window *cfg = bus->sysdata;
	int dev = PCI_SLOT(devfn);

	if (bus->number == cfg->busr.start) {
		/* access only one slot on each root port */
		if (dev > 0)
			return PCIBIOS_DEVICE_NOT_FOUND;
		else
			return pci_generic_config_read32(bus, devfn, where,
							 size, val);
	}

	return pci_generic_config_read(bus, devfn, where, size, val);
}

static int hisi_pcie_acpi_wr_conf(struct pci_bus *bus, u32 devfn,
				  int where, int size, u32 val)
{
	struct pci_config_window *cfg = bus->sysdata;
	int dev = PCI_SLOT(devfn);

	if (bus->number == cfg->busr.start) {
		/* access only one slot on each root port */
		if (dev > 0)
			return PCIBIOS_DEVICE_NOT_FOUND;
		else
			return pci_generic_config_write32(bus, devfn, where,
							  size, val);
	}

	return pci_generic_config_write(bus, devfn, where, size, val);
}

static void __iomem *hisi_pcie_map_bus(struct pci_bus *bus, unsigned int devfn,
				       int where)
{
	struct pci_config_window *cfg = bus->sysdata;
	void __iomem *reg_base = cfg->priv;

	if (bus->number == cfg->busr.start)
		return reg_base + where;
	else
		return pci_ecam_map_bus(bus, devfn, where);
}

static int hisi_pcie_init(struct pci_config_window *cfg)
{
	struct device *dev = cfg->parent;
	struct acpi_device *adev = to_acpi_device(dev);
	struct acpi_pci_root *root = acpi_driver_data(adev);
	struct resource *res;
	void __iomem *reg_base;
	int ret;

	/*
	 * Retrieve RC base and size from a HISI0081 device with _UID
	 * matching our segment.
	 */
	res = devm_kzalloc(dev, sizeof(*res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	ret = acpi_get_rc_resources(dev, "HISI0081", root->segment, res);
	if (ret) {
		dev_err(dev, "can't get rc base address\n");
		return -ENOMEM;
	}

	reg_base = devm_ioremap(dev, res->start, resource_size(res));
	if (!reg_base)
		return -ENOMEM;

	cfg->priv = reg_base;
	return 0;
}

struct pci_ecam_ops hisi_pcie_ops = {
	.bus_shift    = 20,
	.init         =  hisi_pcie_init,
	.pci_ops      = {
		.map_bus    = hisi_pcie_map_bus,
		.read       = hisi_pcie_acpi_rd_conf,
		.write      = hisi_pcie_acpi_wr_conf,
	}
};
#endif

#define PEM_CFG_WR 0x28
#define PEM_CFG_RD 0x30

struct thunder_pem_pci {
	u32		ea_entry[3];
	void __iomem	*pem_reg_base;
};

static int thunder_pem_bridge_read(struct pci_bus *bus, unsigned int devfn,
				   int where, int size, u32 *val)
{
	u64 read_val;
	struct pci_config_window *cfg = bus->sysdata;
	struct thunder_pem_pci *pem_pci = (struct thunder_pem_pci *)cfg->priv;

	if (devfn != 0 || where >= 2048) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	/*
	 * 32-bit accesses only.  Write the address to the low order
	 * bits of PEM_CFG_RD, then trigger the read by reading back.
	 * The config data lands in the upper 32-bits of PEM_CFG_RD.
	 */
	read_val = where & ~3ull;
	writeq(read_val, pem_pci->pem_reg_base + PEM_CFG_RD);
	read_val = readq(pem_pci->pem_reg_base + PEM_CFG_RD);
	read_val >>= 32;

	/*
	 * The config space contains some garbage, fix it up.  Also
	 * synthesize an EA capability for the BAR used by MSI-X.
	 */
	switch (where & ~3) {
	case 0x40:
		read_val &= 0xffff00ff;
		read_val |= 0x00007000; /* Skip MSI CAP */
		break;
	case 0x70: /* Express Cap */
		/* PME interrupt on vector 2*/
		read_val |= (2u << 25);
		break;
	case 0xb0: /* MSI-X Cap */
		/* TableSize=4, Next Cap is EA */
		read_val &= 0xc00000ff;
		read_val |= 0x0003bc00;
		break;
	case 0xb4:
		/* Table offset=0, BIR=0 */
		read_val = 0x00000000;
		break;
	case 0xb8:
		/* BPA offset=0xf0000, BIR=0 */
		read_val = 0x000f0000;
		break;
	case 0xbc:
		/* EA, 1 entry, no next Cap */
		read_val = 0x00010014;
		break;
	case 0xc0:
		/* DW2 for type-1 */
		read_val = 0x00000000;
		break;
	case 0xc4:
		/* Entry BEI=0, PP=0x00, SP=0xff, ES=3 */
		read_val = 0x80ff0003;
		break;
	case 0xc8:
		read_val = pem_pci->ea_entry[0];
		break;
	case 0xcc:
		read_val = pem_pci->ea_entry[1];
		break;
	case 0xd0:
		read_val = pem_pci->ea_entry[2];
		break;
	default:
		break;
	}
	read_val >>= (8 * (where & 3));
	switch (size) {
	case 1:
		read_val &= 0xff;
		break;
	case 2:
		read_val &= 0xffff;
		break;
	default:
		break;
	}
	*val = read_val;
	return PCIBIOS_SUCCESSFUL;
}

static int thunder_pem_config_read(struct pci_bus *bus, unsigned int devfn,
				   int where, int size, u32 *val)
{
	struct pci_config_window *cfg = bus->sysdata;

	if (bus->number < cfg->busr.start ||
	    bus->number > cfg->busr.end)
		return PCIBIOS_DEVICE_NOT_FOUND;

	/*
	 * The first device on the bus is the PEM PCIe bridge.
	 * Special case its config access.
	 */
	if (bus->number == cfg->busr.start)
		return thunder_pem_bridge_read(bus, devfn, where, size, val);

	return pci_generic_config_read(bus, devfn, where, size, val);
}

/*
 * Some of the w1c_bits below also include read-only or non-writable
 * reserved bits, this makes the code simpler and is OK as the bits
 * are not affected by writing zeros to them.
 */
static u32 thunder_pem_bridge_w1c_bits(u64 where_aligned)
{
	u32 w1c_bits = 0;

	switch (where_aligned) {
	case 0x04: /* Command/Status */
	case 0x1c: /* Base and I/O Limit/Secondary Status */
		w1c_bits = 0xff000000;
		break;
	case 0x44: /* Power Management Control and Status */
		w1c_bits = 0xfffffe00;
		break;
	case 0x78: /* Device Control/Device Status */
	case 0x80: /* Link Control/Link Status */
	case 0x88: /* Slot Control/Slot Status */
	case 0x90: /* Root Status */
	case 0xa0: /* Link Control 2 Registers/Link Status 2 */
		w1c_bits = 0xffff0000;
		break;
	case 0x104: /* Uncorrectable Error Status */
	case 0x110: /* Correctable Error Status */
	case 0x130: /* Error Status */
	case 0x160: /* Link Control 4 */
		w1c_bits = 0xffffffff;
		break;
	default:
		break;
	}
	return w1c_bits;
}

/* Some bits must be written to one so they appear to be read-only. */
static u32 thunder_pem_bridge_w1_bits(u64 where_aligned)
{
	u32 w1_bits;

	switch (where_aligned) {
	case 0x1c: /* I/O Base / I/O Limit, Secondary Status */
		/* Force 32-bit I/O addressing. */
		w1_bits = 0x0101;
		break;
	case 0x24: /* Prefetchable Memory Base / Prefetchable Memory Limit */
		/* Force 64-bit addressing */
		w1_bits = 0x00010001;
		break;
	default:
		w1_bits = 0;
		break;
	}
	return w1_bits;
}

static int thunder_pem_bridge_write(struct pci_bus *bus, unsigned int devfn,
				    int where, int size, u32 val)
{
	struct pci_config_window *cfg = bus->sysdata;
	struct thunder_pem_pci *pem_pci = (struct thunder_pem_pci *)cfg->priv;
	u64 write_val, read_val;
	u64 where_aligned = where & ~3ull;
	u32 mask = 0;


	if (devfn != 0 || where >= 2048)
		return PCIBIOS_DEVICE_NOT_FOUND;

	/*
	 * 32-bit accesses only.  If the write is for a size smaller
	 * than 32-bits, we must first read the 32-bit value and merge
	 * in the desired bits and then write the whole 32-bits back
	 * out.
	 */
	switch (size) {
	case 1:
		writeq(where_aligned, pem_pci->pem_reg_base + PEM_CFG_RD);
		read_val = readq(pem_pci->pem_reg_base + PEM_CFG_RD);
		read_val >>= 32;
		mask = ~(0xff << (8 * (where & 3)));
		read_val &= mask;
		val = (val & 0xff) << (8 * (where & 3));
		val |= (u32)read_val;
		break;
	case 2:
		writeq(where_aligned, pem_pci->pem_reg_base + PEM_CFG_RD);
		read_val = readq(pem_pci->pem_reg_base + PEM_CFG_RD);
		read_val >>= 32;
		mask = ~(0xffff << (8 * (where & 3)));
		read_val &= mask;
		val = (val & 0xffff) << (8 * (where & 3));
		val |= (u32)read_val;
		break;
	default:
		break;
	}

	/*
	 * By expanding the write width to 32 bits, we may
	 * inadvertently hit some W1C bits that were not intended to
	 * be written.  Calculate the mask that must be applied to the
	 * data to be written to avoid these cases.
	 */
	if (mask) {
		u32 w1c_bits = thunder_pem_bridge_w1c_bits(where);

		if (w1c_bits) {
			mask &= w1c_bits;
			val &= ~mask;
		}
	}

	/*
	 * Some bits must be read-only with value of one.  Since the
	 * access method allows these to be cleared if a zero is
	 * written, force them to one before writing.
	 */
	val |= thunder_pem_bridge_w1_bits(where_aligned);

	/*
	 * Low order bits are the config address, the high order 32
	 * bits are the data to be written.
	 */
	write_val = (((u64)val) << 32) | where_aligned;
	writeq(write_val, pem_pci->pem_reg_base + PEM_CFG_WR);
	return PCIBIOS_SUCCESSFUL;
}

static int thunder_pem_config_write(struct pci_bus *bus, unsigned int devfn,
				    int where, int size, u32 val)
{
	struct pci_config_window *cfg = bus->sysdata;

	if (bus->number < cfg->busr.start ||
	    bus->number > cfg->busr.end)
		return PCIBIOS_DEVICE_NOT_FOUND;
	/*
	 * The first device on the bus is the PEM PCIe bridge.
	 * Special case its config access.
	 */
	if (bus->number == cfg->busr.start)
		return thunder_pem_bridge_write(bus, devfn, where, size, val);


	return pci_generic_config_write(bus, devfn, where, size, val);
}

#ifdef CONFIG_ACPI
static struct resource *thunder_pem_acpi_init(struct pci_config_window *cfg)
{
	struct device *dev = cfg->parent;
	struct acpi_device *adev = to_acpi_device(dev);
	struct acpi_pci_root *root = acpi_driver_data(adev);
	struct resource *res_pem;
	int ret;

	res_pem = devm_kzalloc(&adev->dev, sizeof(*res_pem), GFP_KERNEL);
	if (!res_pem)
		return NULL;

	ret = acpi_get_rc_resources(dev, "THRX0002", root->segment, res_pem);
	if (ret) {
		dev_err(dev, "can't get rc base address\n");
		return NULL;
	}

	return res_pem;
}
#elif
static inline struct resource *thunder_pem_acpi_init(
						struct pci_config_window *cfg)
{
	return NULL;
}
#endif

static int thunder_pem_init(struct pci_config_window *cfg)
{
	struct device *dev = cfg->parent;
	resource_size_t bar4_start;
	struct resource *res_pem;
	struct thunder_pem_pci *pem_pci;
	struct platform_device *pdev;

	pem_pci = devm_kzalloc(dev, sizeof(*pem_pci), GFP_KERNEL);
	if (!pem_pci)
		return -ENOMEM;

	if (acpi_disabled) {
		pdev = to_platform_device(dev);

		/*
		 * The second register range is the PEM bridge to the PCIe
		 * bus.  It has a different config access method than those
		 * devices behind the bridge.
		 */
		res_pem = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	} else {
		res_pem = thunder_pem_acpi_init(cfg);
	}
	if (!res_pem) {
		dev_err(dev, "missing \"reg[1]\"property\n");
		return -EINVAL;
	}

	pem_pci->pem_reg_base = devm_ioremap(dev, res_pem->start, 0x10000);
	if (!pem_pci->pem_reg_base)
		return -ENOMEM;

	/*
	 * The MSI-X BAR for the PEM and AER interrupts is located at
	 * a fixed offset from the PEM register base.  Generate a
	 * fragment of the synthesized Enhanced Allocation capability
	 * structure here for the BAR.
	 */
	bar4_start = res_pem->start + 0xf00000;
	pem_pci->ea_entry[0] = (u32)bar4_start | 2;
	pem_pci->ea_entry[1] = (u32)(res_pem->end - bar4_start) & ~3u;
	pem_pci->ea_entry[2] = (u32)(bar4_start >> 32);

	cfg->priv = pem_pci;
	return 0;
}

struct pci_ecam_ops pci_thunder_pem_ops = {
	.bus_shift	= 24,
	.init		= thunder_pem_init,
	.pci_ops	= {
		.map_bus	= pci_ecam_map_bus,
		.read		= thunder_pem_config_read,
		.write		= thunder_pem_config_write,
	}
};
