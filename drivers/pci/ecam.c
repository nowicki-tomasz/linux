/*
 * Copyright 2016 Broadcom
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

#include <linux/device.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>

/*
 * On 64 bit systems, we do a single ioremap for the whole config space
 * since we have enough virtual address range available. On 32 bit, do an
 * ioremap per bus.
 */
static const bool per_bus_mapping = !config_enabled(CONFIG_64BIT);

/*
 * struct to hold the mappings of a config space window. This
 * will be allocated with enough entries in win[] to hold all
 * the mappings for the bus range.
 */
struct pci_config_window {
	phys_addr_t		cfgaddr;
	u8			bus_start;
	u8			bus_end;
	u8			bus_shift;
	u8			devfn_shift;
	void __iomem		*win[0];
};

/*
 * helper function provided to implement the pci_ops ->map_bus method
 */
void __iomem *pci_generic_map_bus(struct pci_config_window *cfg,
		 unsigned int busn, unsigned int devfn, int where)
{
	void __iomem *base;

	if (busn < cfg->bus_start || busn > cfg->bus_end)
		return NULL;

	busn -= cfg->bus_start;
	if (per_bus_mapping)
		base = cfg->win[busn];
	else
		base = cfg->win[0] + (busn << cfg->bus_shift);
	return base + (devfn << cfg->devfn_shift) + where;
}

/*
 * Create a PCI config space window
 *  - reserve mem region
 *  - alloc struct pci_config_window with space for all mappings
 *  - ioremap the config space
 */
struct pci_config_window *pci_generic_map_config(phys_addr_t addr,
	u8 bus_start, u8 bus_end, u8 bus_shift, u8 devfn_shift)
{
	struct pci_config_window *cfg;
	unsigned int bus_range, bsz, mapsz;
	int i, nidx;

	if (bus_end < bus_start)
		return ERR_PTR(-EINVAL);

	bus_range = bus_end - bus_start + 1;
	bsz = 1 << bus_shift;
	nidx = per_bus_mapping ? bus_range : 1;
	mapsz = per_bus_mapping ? bsz : bus_range * bsz;
	cfg = kzalloc(sizeof(*cfg) + nidx * sizeof(cfg->win[0]), GFP_KERNEL);
	if (!cfg)
		return ERR_PTR(-ENOMEM);

	cfg->bus_start = bus_start;
	cfg->bus_end = bus_end;
	cfg->bus_shift = bus_shift;
	cfg->devfn_shift = devfn_shift;

	if (!request_mem_region(addr, bus_range * bsz, "Configuration Space"))
		goto err_exit;

	/* cfgaddr has to be set after request_mem_region */
	cfg->cfgaddr = addr;

	for (i = 0; i < nidx; i++) {
		cfg->win[i] = ioremap(addr + i * mapsz, mapsz);
		if (!cfg->win[i])
			goto err_exit;
	}
	return cfg;

err_exit:
	pci_generic_unmap_config(cfg);
	return ERR_PTR(-ENOMEM);
}

/*
 * Free a config space mapping
 */
void pci_generic_unmap_config(struct pci_config_window *cfg)
{
	unsigned int bus_range;
	int i, nidx;

	bus_range = cfg->bus_end - cfg->bus_start + 1;
	nidx = per_bus_mapping ? bus_range : 1;
	for (i = 0; i < nidx; i++)
		if (cfg->win[i])
			iounmap(cfg->win[i]);
	if (cfg->cfgaddr)
		release_mem_region(cfg->cfgaddr, bus_range << cfg->bus_shift);
	kfree(cfg);
}
