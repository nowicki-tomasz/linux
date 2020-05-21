// SPDX-License-Identifier: GPL-2.0

/*
 * Memory Mapped IO clock driver
 *
 * Copyright (C) 2018 Cadence Design Systems, Inc.
 *
 * Authors:
 *	Tomasz <tn@semihalf.com>
 */

#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>

/**
 * struct clk_fixed_rate - fixed-rate clock
 * @hw:		handle between common and hardware-specific interfaces
 * @base:	register based address
 */
struct clk_mmio_rate {
	struct clk_hw	hw;
	void __iomem	*base;
};

#define CLK_MMIO_RATE	0x0
#define CLK_MMIO_FALGS	0x4

#define to_clk_mmio(_hw) container_of(_hw, struct clk_mmio_rate, hw)
#define CLK_MMIO_REG(_hw, reg) to_clk_mmio(_hw)->base + (reg)


static unsigned long clk_mmio_rate_recalc_rate(struct clk_hw *hw,
					       unsigned long parent_rate)
{
	long rate = readl(CLK_MMIO_REG(hw, CLK_MMIO_RATE));

	pr_err("%s 1 parent_rate %ld rate %ld\n", __func__, parent_rate, rate);

	return rate;
}

int clk_mmio_rate_set_rate(struct clk_hw *hw, unsigned long rate,
			   unsigned long parent_rate)
{
	pr_err("%s 1 rate 0x%lx parent_rate 0x%lx\n", __func__, rate, parent_rate);
	writel(rate, CLK_MMIO_REG(hw, CLK_MMIO_RATE));
	return 0;
}

static long clk_mmio_round_rate(struct clk_hw *hw, unsigned long rate,
				  unsigned long *parent_rate)
{
	return rate;
}

static const struct clk_ops clk_mmio_ops = {
	.recalc_rate	= clk_mmio_rate_recalc_rate,
	.round_rate	= clk_mmio_round_rate,
	.set_rate	= clk_mmio_rate_set_rate,
};

static int of_mmio_clk_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = dev->of_node;
	const char *clk_name = node->name;
	struct clk_mmio_rate *mmio_clk;
	struct clk_hw *hw;
	struct clk_init_data init;
	int ret;

	pr_err("%s 1\n", __func__);

	mmio_clk = devm_kzalloc(dev, sizeof(*mmio_clk), GFP_KERNEL);
	if (!mmio_clk)
		return -ENOMEM;

	pr_err("%s 2\n", __func__);

	mmio_clk->base = of_iomap(node, 0);
	if (!mmio_clk->base) {
		pr_err("%pOFn: failed to map address\n", node);
		return -EIO;
	}

	pr_err("%s 3\n", __func__);

	of_property_read_string(node, "clock-output-names", &clk_name);
	init.name = clk_name;
	init.ops = &clk_mmio_ops;
	init.flags = readl(mmio_clk->base + CLK_MMIO_FALGS);

	pr_err("%s 31 read flags 0x%lx\n", __func__, (long)init.flags);

	init.parent_names = NULL;
	init.num_parents = 0;

	mmio_clk->hw.init = &init;

	/* register the clock */
	hw = &mmio_clk->hw;
	ret = clk_hw_register(dev, hw);
	if (ret) {
		return ret;
	}

	pr_err("%s 4\n", __func__);

	ret = of_clk_add_provider(node, of_clk_src_simple_get, hw->clk);
	if (ret) {
		clk_hw_unregister(hw);
		return ret;
	}

	platform_set_drvdata(pdev, mmio_clk);
	return 0;
}

static int of_mmio_clk_remove(struct platform_device *pdev)
{
	struct clk_mmio_rate *mmio_clk = platform_get_drvdata(pdev);

	of_clk_del_provider(pdev->dev.of_node);
	clk_hw_unregister(&mmio_clk->hw);
	iounmap(mmio_clk->base);

	return 0;
}

static const struct of_device_id of_mmio_clk_ids[] = {
	{ .compatible = "mmio-clock" },
	{ }
};
MODULE_DEVICE_TABLE(of, of_mmio_clk_ids);

static struct platform_driver of_mmio_clk_driver = {
	.driver = {
		.name = "of_mmio_clk",
		.of_match_table = of_mmio_clk_ids,
	},
	.probe = of_mmio_clk_probe,
	.remove = of_mmio_clk_remove,
};
module_platform_driver(of_mmio_clk_driver);

MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Memory Mapped IO clock driver");
MODULE_LICENSE("GPL v2");
