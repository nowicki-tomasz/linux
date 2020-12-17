/*
 * VFIO platform driver specialized for XHCI reset
 * reset code is inherited from XHCI native driver
 *
 * Copyright 2016 Marvell Semiconductors, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/device.h>
#include <linux/delay.h>
//#include <linux/regulator/consumer.h>
//#include <linux/regulator/driver.h>

#include "../vfio_platform_private.h"

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Tomasz Nowicki <tn@semihalf.com>"
#define DRIVER_DESC     "Reset support for Qualcomm GENI SE QUP vfio platform device"

/****************************************************************/
/* GENIQUP */

/* EC + SPI */
int vfio_platform_geni_ec_reset(struct vfio_platform_device *vdev)
{
	return 0;
}
module_vfio_reset_handler("google,cros-ec-spi", vfio_platform_geni_ec_reset);

/* GENIQUP SPI */

int vfio_platform_geni_spi_reset(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	int ret;

	dev_err(dev, "%s starting\n", __func__);

	ret = devm_of_platform_populate(dev);
	if (ret) {
		dev_err(dev, "failed to populate - %d\n", ret);
		return ret;
	}

	dev_err(dev, "%s finishing\n", __func__);

	return 0;
}
module_vfio_reset_handler("qcom,geni-spi", vfio_platform_geni_spi_reset);

/* MDSS DSI bridge + I2C */
int vfio_platform_geni_dsi_bridge_reset(struct vfio_platform_device *vdev)
{
	return 0;
}
module_vfio_reset_handler("ti,sn65dsi86", vfio_platform_geni_dsi_bridge_reset);

/* touchscreen + I2C */
int vfio_platform_geni_touchscreen_reset(struct vfio_platform_device *vdev)
{
	return 0;
}
module_vfio_reset_handler("hid-over-i2c", vfio_platform_geni_touchscreen_reset);

/* GENIQUP I2C */

int vfio_platform_geni_i2c_reset(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	int ret;

	dev_err(dev, "%s starting\n", __func__);

	ret = devm_of_platform_populate(dev);
	if (ret) {
		dev_err(dev, "failed to populate - %d\n", ret);
		return ret;
	}

	dev_err(dev, "%s finishing\n", __func__);

	return 0;
}
module_vfio_reset_handler("qcom,geni-i2c", vfio_platform_geni_i2c_reset);

/* bluetooth + UART */
int vfio_platform_geni_bluetooth_reset(struct vfio_platform_device *vdev)
{
	return 0;
}
module_vfio_reset_handler("qcom,wcn3991-bt", vfio_platform_geni_bluetooth_reset);

/* GENIQUP UART */

int vfio_platform_geni_uart_reset(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	int ret;

	dev_err(dev, "%s starting\n", __func__);

	ret = devm_of_platform_populate(dev);
	if (ret) {
		dev_err(dev, "failed to populate - %d\n", ret);
		return ret;
	}

	dev_err(dev, "%s finishing\n", __func__);

	return 0;
}
module_vfio_reset_handler("qcom,geni-uart", vfio_platform_geni_uart_reset);

/* GENIQUP BUS */

//static const struct of_device_id geni_dt_match_table[] = {
//	{ .compatible = "qcom,geni-uart", },
//	{ }
//};

int of_platform_bus_create_debug(struct device_node *bus,
				  const struct of_device_id *matches,
				  const struct of_dev_auxdata *lookup,
				  struct device *parent, bool strict);

int vfio_platform_qcom_geniqup_reset(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct device_node *root = dev->of_node;
	struct device_node *child;
	int rc = 0;
//	int ret;

	dev_err(dev, "%s starting\n", __func__);

//	ret = of_platform_populate(dev->of_node, geni_dt_match_table, NULL, dev);
//	if (ret) {
//		dev_err(dev, "failed to populate - %d\n", ret);
//		return ret;
//	}



	root = root ? of_node_get(root) : of_find_node_by_path("/");
	if (!root)
		return -EINVAL;

	pr_err("%s()\n", __func__);
	pr_err(" starting at: %pOF\n", root);

	for_each_child_of_node(root, child) {

		pr_err(" chdild %s checking \n", child->name);

//		if (!of_device_is_compatible(child, "qcom,geni-uart") &&
//		    !of_device_is_compatible(child, "qcom,geni-i2c"))
//			continue;

		pr_err(" chdild %s creating\n", child->name);

		rc = of_platform_bus_create_debug(child, NULL, NULL, dev, true);
		if (rc) {
			of_node_put(child);
			break;
		}

		pr_err(" chdild %s done\n", child->name);
	}
	of_node_set_flag(root, OF_POPULATED_BUS);

	of_node_put(root);

	dev_err(dev, "%s finishing\n", __func__);

	return 0;
}

module_vfio_reset_handler("qcom,geni-se-qup", vfio_platform_qcom_geniqup_reset);

/****************************************************************/
/* GPU PANEL + BACKLIGHT */

int vfio_platform_qcom_backlight(struct vfio_platform_device *vdev)
{

	return 0;
}
module_vfio_reset_handler("pwm-backlight", vfio_platform_qcom_backlight);

int vfio_platform_qcom_panel(struct vfio_platform_device *vdev)
{

	return 0;
}
module_vfio_reset_handler("boe,nv133fhm-n62", vfio_platform_qcom_panel);

/****************************************************************/
/* AUDIO CODEC */

int vfio_platform_qcom_audio_codec(struct vfio_platform_device *vdev)
{

	return 0;
}
module_vfio_reset_handler("maxim,max98357a", vfio_platform_qcom_audio_codec);

/* MDSS children */

int vfio_platform_qcom_dpu(struct vfio_platform_device *vdev)
{

	return 0;
}
module_vfio_reset_handler("qcom,sc7180-dpu", vfio_platform_qcom_dpu);

int vfio_platform_qcom_dsi(struct vfio_platform_device *vdev)
{

	return 0;
}
module_vfio_reset_handler("qcom,mdss-dsi-ctrl", vfio_platform_qcom_dsi);

int vfio_platform_qcom_dsi_phy(struct vfio_platform_device *vdev)
{

	return 0;
}
module_vfio_reset_handler("qcom,dsi-phy-10nm", vfio_platform_qcom_dsi_phy);

int vfio_platform_qcom_dp(struct vfio_platform_device *vdev)
{

	return 0;
}
module_vfio_reset_handler("qcom,sc7180-dp", vfio_platform_qcom_dp);

/* MDSS parent */

int vfio_platform_qcom_mdss(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct device_node *root = dev->of_node;
	struct device_node *child;
	int rc = 0;

	dev_err(dev, "%s starting\n", __func__);

	root = root ? of_node_get(root) : of_find_node_by_path("/");
	if (!root)
		return -EINVAL;

	pr_err("%s()\n", __func__);
	pr_err(" starting at: %pOF\n", root);

	for_each_child_of_node(root, child) {

		pr_err(" chdild %s checking \n", child->name);

		rc = of_platform_bus_create_debug(child, NULL, NULL, dev, true);
		if (rc) {
			of_node_put(child);
			break;
		}

		pr_err(" chdild %s done\n", child->name);
	}
	of_node_set_flag(root, OF_POPULATED_BUS);

	of_node_put(root);

	dev_err(dev, "%s finishing\n", __func__);

	return 0;
}
module_vfio_reset_handler("qcom,sc7180-mdss", vfio_platform_qcom_mdss);

/* DISPLAY clocks */

int vfio_platform_qcom_disp_clk(struct vfio_platform_device *vdev)
{

	return 0;
}
module_vfio_reset_handler("qcom,sc7180-dispcc", vfio_platform_qcom_disp_clk);

/* GPU and GMU */

int vfio_platform_qcom_gmu(struct vfio_platform_device *vdev)
{

	return 0;
}
module_vfio_reset_handler("qcom,adreno-gmu-618.0", vfio_platform_qcom_gmu);

int vfio_platform_qcom_gpu(struct vfio_platform_device *vdev)
{
	struct device *dev = vdev->device;
	struct platform_device *pdev;
	struct device_node *node;

	/*
	 * GMU is instantiated by GPU.
	 * Check if there is a GMU phandle and set it up.
	 */
	node = of_parse_phandle(dev->of_node, "qcom,gmu", 0);
	if (!node) {
		dev_err(dev, "%s no GMU of_node!!!\n", __func__);
		return -ENODEV;
	}

	pdev = of_find_device_by_node(node);
	if (!pdev) {
		dev_err(dev, "%s no GMU platform dev!!!\n", __func__);
		return -ENODEV;
	}

	/* Create IOMMU group which allows to assign GMU to VM */
	of_dma_configure(&pdev->dev, node, true);
	return 0;
}
module_vfio_reset_handler("qcom,adreno-618.0", vfio_platform_qcom_gpu);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
