/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2014 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 */

#ifndef _PCI_HOST_COMMON_H
#define _PCI_HOST_COMMON_H

#include <linux/kernel.h>
#include <linux/platform_device.h>

struct gen_pci {
	struct pci_host_bridge		host;
	struct resource			*bus_range;
	unsigned int			bus_shift;
	struct resource			cfgres;
	struct pci_config_window	*cfg;
	struct pci_ops			*ops;
	struct list_head		resources;
};

int pci_host_common_probe(struct platform_device *pdev,
			  struct gen_pci *pci);
void __iomem *gen_pci_map_cfg_bus(struct pci_bus *bus,
				  unsigned int devfn, int where);

#endif /* _PCI_HOST_COMMON_H */
