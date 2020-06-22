// SPDX-License-Identifier: GPL-2.0

/*
 * Memory Mapped IO clock driver
 *
* Copyright (C) 2020, Semihalf
 *	Author: Tomasz Nowicki <tn@semihalf.com>
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

#define CLK_MMIO_RATE		0x0
#define CLK_MMIO_FALGS		0x8	// READONLY
#define CLK_MMIO_PREPARE	0x10
#define CLK_MMIO_ENABLE		0x14

#define to_clk_mmio(_hw) container_of(_hw, struct clk_mmio_rate, hw)
#define CLK_MMIO_REG(_hw, reg) to_clk_mmio(_hw)->base + (reg)

static int clk_mmio_prepare(struct clk_hw *hw)
{
	writel(1, CLK_MMIO_REG(hw, CLK_MMIO_PREPARE));
	return 0;
}

static void clk_mmio_unprepare(struct clk_hw *hw)
{
	writel(0, CLK_MMIO_REG(hw, CLK_MMIO_PREPARE));
}

static int clk_mmio_enable(struct clk_hw *hw)
{
	writel(1, CLK_MMIO_REG(hw, CLK_MMIO_ENABLE));
	return 0;
}

static void clk_mmio_disable(struct clk_hw *hw)
{
	writel(0, CLK_MMIO_REG(hw, CLK_MMIO_ENABLE));
}

static unsigned long clk_mmio_recalc_rate(struct clk_hw *hw,
					  unsigned long parent_rate)
{
	return readq(CLK_MMIO_REG(hw, CLK_MMIO_RATE));
}

int clk_mmio_set_rate(struct clk_hw *hw, unsigned long rate,
		      unsigned long parent_rate)
{
	writeq(rate, CLK_MMIO_REG(hw, CLK_MMIO_RATE));
	return 0;
}

static long clk_mmio_round_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long *parent_rate)
{
	return rate;
}

static const struct clk_ops clk_mmio_ops = {
	.prepare	= clk_mmio_prepare,
	.unprepare	= clk_mmio_unprepare,
	.enable		= clk_mmio_enable,
	.disable	= clk_mmio_disable,
	.recalc_rate	= clk_mmio_recalc_rate,
	.set_rate	= clk_mmio_set_rate,
	.round_rate	= clk_mmio_round_rate,
};

static int of_mmio_clk_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = dev->of_node;
	struct clk_mmio_rate *mmio_clk;
	struct clk_init_data init = { };
	static int instance;
	struct clk_hw *hw;
	int ret;

	mmio_clk = devm_kzalloc(dev, sizeof(*mmio_clk), GFP_KERNEL);
	if (!mmio_clk)
		return -ENOMEM;

	mmio_clk->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(mmio_clk->base))
		return PTR_ERR(mmio_clk->base);

	init.name = devm_kasprintf(dev, GFP_KERNEL, "%s-%d", node->name,
				   instance++);
	init.ops = &clk_mmio_ops;
	init.flags = readq(mmio_clk->base + CLK_MMIO_FALGS);
	mmio_clk->hw.init = &init;

	hw = &mmio_clk->hw;
	ret = devm_clk_hw_register(dev, hw);
	if (ret) {
		dev_err(dev, "Failed to register clock with %d\n", ret);
		return ret;
	}

	ret = devm_of_clk_add_hw_provider(dev, of_clk_hw_simple_get, hw);
	if (ret)
		dev_err(dev, "Failed to add clock provider with %d\n", ret);

	return ret;
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
};
module_platform_driver(of_mmio_clk_driver);

MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Memory Mapped IO clock driver");
MODULE_LICENSE("GPL v2");
