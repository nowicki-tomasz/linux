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

static void set_val(u32 v, int where, int size, u32 *val)
{
	int shift = (where & 3) * 8;

	pr_debug("set_val %04x: %08x\n", (unsigned)(where & ~3), v);
	v >>= shift;
	if (size == 1)
		v &= 0xff;
	else if (size == 2)
		v &= 0xffff;
	*val = v;
}

static int handle_ea_bar(u32 e0, int bar, struct pci_bus *bus,
			 unsigned int devfn, int where, int size, u32 *val)
{
	void __iomem *addr;
	u32 v;

	/* Entries are 16-byte aligned; bits[2,3] select word in entry */
	int where_a = where & 0xc;

	if (where_a == 0) {
		set_val(e0, where, size, val);
		return PCIBIOS_SUCCESSFUL;
	}
	if (where_a == 0x4) {
		addr = bus->ops->map_bus(bus, devfn, bar); /* BAR 0 */
		if (!addr) {
			*val = ~0;
			return PCIBIOS_DEVICE_NOT_FOUND;
		}
		v = readl(addr);
		v &= ~0xf;
		v |= 2; /* EA entry-1. Base-L */
		set_val(v, where, size, val);
		return PCIBIOS_SUCCESSFUL;
	}
	if (where_a == 0x8) {
		u32 barl_orig;
		u32 barl_rb;

		addr = bus->ops->map_bus(bus, devfn, bar); /* BAR 0 */
		if (!addr) {
			*val = ~0;
			return PCIBIOS_DEVICE_NOT_FOUND;
		}
		barl_orig = readl(addr + 0);
		writel(0xffffffff, addr + 0);
		barl_rb = readl(addr + 0);
		writel(barl_orig, addr + 0);
		/* zeros in unsettable bits */
		v = ~barl_rb & ~3;
		v |= 0xc; /* EA entry-2. Offset-L */
		set_val(v, where, size, val);
		return PCIBIOS_SUCCESSFUL;
	}
	if (where_a == 0xc) {
		addr = bus->ops->map_bus(bus, devfn, bar + 4); /* BAR 1 */
		if (!addr) {
			*val = ~0;
			return PCIBIOS_DEVICE_NOT_FOUND;
		}
		v = readl(addr); /* EA entry-3. Base-H */
		set_val(v, where, size, val);
		return PCIBIOS_SUCCESSFUL;
	}
	return PCIBIOS_DEVICE_NOT_FOUND;
}

static int thunder_ecam_p2_config_read(struct pci_bus *bus, unsigned int devfn,
				       int where, int size, u32 *val)
{
	struct pci_config_window *cfg = bus->sysdata;
	int where_a = where & ~3;
	void __iomem *addr;
	u32 node_bits;
	u32 v;

	/* EA Base[63:32] may be missing some bits ... */
	switch (where_a) {
	case 0xa8:
	case 0xbc:
	case 0xd0:
	case 0xe4:
		break;
	default:
		return pci_generic_config_read(bus, devfn, where, size, val);
	}

	addr = bus->ops->map_bus(bus, devfn, where_a);
	if (!addr) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	v = readl(addr);

	/*
	 * Bit 44 of the 64-bit Base must match the same bit in
	 * the config space access window.  Since we are working with
	 * the high-order 32 bits, shift everything down by 32 bits.
	 */
	node_bits = (cfg->res.start >> 32) & (1 << 12);

	v |= node_bits;
	set_val(v, where, size, val);

	return PCIBIOS_SUCCESSFUL;
}

static int thunder_ecam_config_read(struct pci_bus *bus, unsigned int devfn,
				    int where, int size, u32 *val)
{
	u32 v;
	u32 vendor_device;
	u32 class_rev;
	void __iomem *addr;
	int cfg_type;
	int where_a = where & ~3;

	addr = bus->ops->map_bus(bus, devfn, 0xc);
	if (!addr) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	v = readl(addr);

	/* Check for non type-00 header */
	cfg_type = (v >> 16) & 0x7f;

	addr = bus->ops->map_bus(bus, devfn, 8);
	if (!addr) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	class_rev = readl(addr);
	if (class_rev == 0xffffffff)
		goto no_emulation;

	if ((class_rev & 0xff) >= 8) {
		/* Pass-2 handling */
		if (cfg_type)
			goto no_emulation;
		return thunder_ecam_p2_config_read(bus, devfn, where,
						   size, val);
	}

	/*
	 * All BARs have fixed addresses specified by the EA
	 * capability; they must return zero on read.
	 */
	if (cfg_type == 0 &&
	    ((where >= 0x10 && where < 0x2c) ||
	     (where >= 0x1a4 && where < 0x1bc))) {
		/* BAR or SR-IOV BAR */
		*val = 0;
		return PCIBIOS_SUCCESSFUL;
	}

	addr = bus->ops->map_bus(bus, devfn, 0);
	if (!addr) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	vendor_device = readl(addr);
	if (vendor_device == 0xffffffff)
		goto no_emulation;

	pr_debug("%04x:%04x - Fix pass#: %08x, where: %03x, devfn: %03x\n",
		 vendor_device & 0xffff, vendor_device >> 16, class_rev,
		 (unsigned) where, devfn);

	/* Check for non type-00 header */
	if (cfg_type == 0) {
		bool has_msix;
		bool is_nic = (vendor_device == 0xa01e177d);
		bool is_tns = (vendor_device == 0xa01f177d);

		addr = bus->ops->map_bus(bus, devfn, 0x70);
		if (!addr) {
			*val = ~0;
			return PCIBIOS_DEVICE_NOT_FOUND;
		}
		/* E_CAP */
		v = readl(addr);
		has_msix = (v & 0xff00) != 0;

		if (!has_msix && where_a == 0x70) {
			v |= 0xbc00; /* next capability is EA at 0xbc */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a == 0xb0) {
			addr = bus->ops->map_bus(bus, devfn, where_a);
			if (!addr) {
				*val = ~0;
				return PCIBIOS_DEVICE_NOT_FOUND;
			}
			v = readl(addr);
			if (v & 0xff00)
				pr_err("Bad MSIX cap header: %08x\n", v);
			v |= 0xbc00; /* next capability is EA at 0xbc */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a == 0xbc) {
			if (is_nic)
				v = 0x40014; /* EA last in chain, 4 entries */
			else if (is_tns)
				v = 0x30014; /* EA last in chain, 3 entries */
			else if (has_msix)
				v = 0x20014; /* EA last in chain, 2 entries */
			else
				v = 0x10014; /* EA last in chain, 1 entry */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a >= 0xc0 && where_a < 0xd0)
			/* EA entry-0. PP=0, BAR0 Size:3 */
			return handle_ea_bar(0x80ff0003,
					     0x10, bus, devfn, where,
					     size, val);
		if (where_a >= 0xd0 && where_a < 0xe0 && has_msix)
			 /* EA entry-1. PP=0, BAR4 Size:3 */
			return handle_ea_bar(0x80ff0043,
					     0x20, bus, devfn, where,
					     size, val);
		if (where_a >= 0xe0 && where_a < 0xf0 && is_tns)
			/* EA entry-2. PP=0, BAR2, Size:3 */
			return handle_ea_bar(0x80ff0023,
					     0x18, bus, devfn, where,
					     size, val);
		if (where_a >= 0xe0 && where_a < 0xf0 && is_nic)
			/* EA entry-2. PP=4, VF_BAR0 (9), Size:3 */
			return handle_ea_bar(0x80ff0493,
					     0x1a4, bus, devfn, where,
					     size, val);
		if (where_a >= 0xf0 && where_a < 0x100 && is_nic)
			/* EA entry-3. PP=4, VF_BAR4 (d), Size:3 */
			return handle_ea_bar(0x80ff04d3,
					     0x1b4, bus, devfn, where,
					     size, val);
	} else if (cfg_type == 1) {
		bool is_rsl_bridge = devfn == 0x08;
		bool is_rad_bridge = devfn == 0xa0;
		bool is_zip_bridge = devfn == 0xa8;
		bool is_dfa_bridge = devfn == 0xb0;
		bool is_nic_bridge = devfn == 0x10;

		if (where_a == 0x70) {
			addr = bus->ops->map_bus(bus, devfn, where_a);
			if (!addr) {
				*val = ~0;
				return PCIBIOS_DEVICE_NOT_FOUND;
			}
			v = readl(addr);
			if (v & 0xff00)
				pr_err("Bad PCIe cap header: %08x\n", v);
			v |= 0xbc00; /* next capability is EA at 0xbc */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a == 0xbc) {
			if (is_nic_bridge)
				v = 0x10014; /* EA last in chain, 1 entry */
			else
				v = 0x00014; /* EA last in chain, no entries */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a == 0xc0) {
			if (is_rsl_bridge || is_nic_bridge)
				v = 0x0101; /* subordinate:secondary = 1:1 */
			else if (is_rad_bridge)
				v = 0x0202; /* subordinate:secondary = 2:2 */
			else if (is_zip_bridge)
				v = 0x0303; /* subordinate:secondary = 3:3 */
			else if (is_dfa_bridge)
				v = 0x0404; /* subordinate:secondary = 4:4 */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a == 0xc4 && is_nic_bridge) {
			/* Enabled, not-Write, SP=ff, PP=05, BEI=6, ES=4 */
			v = 0x80ff0564;
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a == 0xc8 && is_nic_bridge) {
			v = 0x00000002; /* Base-L 64-bit */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a == 0xcc && is_nic_bridge) {
			v = 0xfffffffe; /* MaxOffset-L 64-bit */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a == 0xd0 && is_nic_bridge) {
			v = 0x00008430; /* NIC Base-H */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
		if (where_a == 0xd4 && is_nic_bridge) {
			v = 0x0000000f; /* MaxOffset-H */
			set_val(v, where, size, val);
			return PCIBIOS_SUCCESSFUL;
		}
	}
no_emulation:
	return pci_generic_config_read(bus, devfn, where, size, val);
}

static int thunder_ecam_config_write(struct pci_bus *bus, unsigned int devfn,
				     int where, int size, u32 val)
{
	/*
	 * All BARs have fixed addresses; ignore BAR writes so they
	 * don't get corrupted.
	 */
	if ((where >= 0x10 && where < 0x2c) ||
	    (where >= 0x1a4 && where < 0x1bc))
		/* BAR or SR-IOV BAR */
		return PCIBIOS_SUCCESSFUL;

	return pci_generic_config_write(bus, devfn, where, size, val);
}

struct pci_ecam_ops pci_thunder_ecam_ops = {
	.bus_shift	= 20,
	.pci_ops	= {
		.map_bus        = pci_ecam_map_bus,
		.read           = thunder_ecam_config_read,
		.write          = thunder_ecam_config_write,
	}
};
