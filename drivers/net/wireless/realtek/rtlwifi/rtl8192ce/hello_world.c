/******************************************************************************
 *
 * Copyright(c) 2017  Semihalf sp. z o.o.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Tomasz Nowicki <tn@semihalf.com>
 *
 *****************************************************************************/

#include <linux/module.h>
#include <linux/pci.h>

static const struct pci_device_id hello_world_pci_ids[] = {
	{ PCI_VDEVICE(REALTEK, 0x8176), 0 },
	{ 0, },
};

MODULE_DEVICE_TABLE(pci, hello_world_pci_ids);

int hello_world_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct resource res;
	int err;

	pr_info("Fake WiFi driver successfully loaded !!!\n");

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable new PCI device\n");
		return err;
	}

	err = pci_request_regions(pdev, "hello world resources");
	if (err) {
		dev_err(&pdev->dev, "Can't obtain PCI resources\n");
		return err;
	}

	res.start = pci_resource_start(pdev, 2);
	res.end = pci_resource_end(pdev, 2);
	res.flags = pci_resource_flags(pdev, 2);

	dev_info(&pdev->dev, "Available device resources: BAR[2] = %pR\n",
			 &res);

	return 0;
}

void hello_world_remove(struct pci_dev *pdev)
{
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static struct pci_driver hello_world_driver = {
	.name = "hello world",
	.id_table = hello_world_pci_ids,
	.probe = hello_world_probe,
	.remove = hello_world_remove,
};

module_pci_driver(hello_world_driver);
