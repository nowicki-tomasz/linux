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
#ifndef DRIVERS_PCI_ECAM_H
#define DRIVERS_PCI_ECAM_H

#include <linux/kernel.h>
#include <linux/platform_device.h>

/*
 * struct to hold pci ops and bus shift of the config window
 * for a PCI controller.
 */
struct pci_config_window;
struct pci_generic_ecam_ops {
	unsigned int			bus_shift;
	struct pci_ops			pci_ops;
	int				(*init)(struct device *,
						struct pci_config_window *);
};

/*
 * struct to hold the mappings of a config space window. This
 * will be allocated with enough entries in win[] to hold all
 * the mappings for the bus range.
 */
struct pci_config_window {
	phys_addr_t			cfgaddr;
	u16				domain;
	u8				bus_start;
	u8				bus_end;
	void				*priv;
	struct pci_generic_ecam_ops	*ops;
	void __iomem			*win[0];
};

/* create and free for pci_config_window */
struct pci_config_window *pci_generic_ecam_create(struct device *dev,
				phys_addr_t addr, u8 bus_start, u8 bus_end,
				struct pci_generic_ecam_ops *ops);
void pci_generic_ecam_free(struct pci_config_window *cfg);

/* map_bus when ->sysdata is an instance of pci_config_window */
void __iomem *pci_generic_ecam_map_bus(struct pci_bus *bus, unsigned int devfn,
				       int where);
/* default ECAM ops, bus shift 20, generic read and write */
extern struct pci_generic_ecam_ops pci_generic_ecam_default_ops;

#ifdef CONFIG_PCI_HOST_GENERIC
/* for DT based pci controllers that support ECAM */
int pci_host_common_probe(struct platform_device *pdev,
			  struct pci_generic_ecam_ops *ops);
#endif
#endif
