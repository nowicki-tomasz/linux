// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio driver for the paravirtualized VFIO platform device
 *
 * Copyright (C) 2020 Semihalf
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/gpio/driver.h>
#include <linux/module.h>
#include <linux/pinctrl/machine.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_transport.h>
#include <uapi/linux/virtio_vfio.h>

#include "core.h"
#include "pinctrl-utils.h"

struct vfio_pinctrl_dev {
	struct device		*dev;
	struct virtio_device	*vdev;
	struct virtio_trans	*virtio_trans;
	struct pinctrl_dev	*pctrl;
	struct pinctrl_desc	desc;
	struct gpio_chip	chip;
};

struct vfio_pingroup {
	const char *name;
	const unsigned *pins;
	unsigned npins;
};

static const struct pinctrl_pin_desc virtio_pinctrl_pins[] = {
	PINCTRL_PIN(0, "GPIO_0"),
};

#define VPINGROUP(id)	\
	{						\
		.name = "gpio" #id,			\
		.pins = gpio##id##_pins,		\
		.npins = ARRAY_SIZE(gpio##id##_pins),	\
	}

#define DECLARE_GPIO_PINS(pin) \
	static const unsigned int gpio##pin##_pins[] = { pin }

DECLARE_GPIO_PINS(0);
static const struct vfio_pingroup virtio_pinctrl_groups[] = {
	[0] = VPINGROUP(0),
};

static int virtio_get_groups_count(struct pinctrl_dev *pctldev)
{
	return ARRAY_SIZE(virtio_pinctrl_groups);
}

static const char *virtio_get_group_name(struct pinctrl_dev *pctldev,
				      unsigned group)
{
	return virtio_pinctrl_groups[group].name;
}

static int virtio_get_group_pins(struct pinctrl_dev *pctldev,
			      unsigned group,
			      const unsigned **pins,
			      unsigned *num_pins)
{
	*pins = virtio_pinctrl_groups[group].pins;
	*num_pins = virtio_pinctrl_groups[group].npins;
	return 0;
}

static const struct pinctrl_ops virtio_pinctrl_ops = {
	.get_groups_count	= virtio_get_groups_count,
	.get_group_name		= virtio_get_group_name,
	.get_group_pins		= virtio_get_group_pins,
	.dt_node_to_map		= pinconf_generic_dt_node_to_map_group,
	.dt_free_map		= pinctrl_utils_free_map,
};

static int virtio_config_group_get(struct pinctrl_dev *pctldev,
				   unsigned int group,
				   unsigned long *config)
{
	return 0;
}

static int virtio_config_group_set(struct pinctrl_dev *pctldev,
				   unsigned group,
				   unsigned long *configs,
				   unsigned num_configs)
{
	struct vfio_pinctrl_dev *vpctrl = pinctrl_dev_get_drvdata(pctldev);
	struct virtio_vfio_pinctrl_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PINCTRL,
			.hdr.req_type = VIRTIO_VFIO_REQ_PINCTRL_SELECT,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	dev_err(vpctrl->dev, "~~~~~~~~ %s pinctrl name %s\n",
			__func__, dev_name(vpctrl->dev));

	return WARN_ON(virtio_transport_send_req_sync(vpctrl->virtio_trans, &msg,
						      sizeof(msg)));
}

static const struct pinconf_ops virtio_pinconf_ops = {
	.is_generic		= true,
	.pin_config_group_get	= virtio_config_group_get,
	.pin_config_group_set	= virtio_config_group_set,
};

static int virtio_gpio_direction_input(struct gpio_chip *chip, unsigned offset)
{
	struct vfio_pinctrl_dev *vpctrl = gpiochip_get_data(chip);
	struct virtio_vfio_gpio_dir_input_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PINCTRL,
			.hdr.req_type = VIRTIO_VFIO_REQ_GPIO_DIR_IN,
			.hdr.req_len = sizeof(uint64_t),
			.offset = offset,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	return WARN_ON(virtio_transport_send_req_sync(vpctrl->virtio_trans, &msg,
						      sizeof(msg)));
}

static int virtio_gpio_direction_output(struct gpio_chip *chip, unsigned offset,
					int value)
{
	struct vfio_pinctrl_dev *vpctrl = gpiochip_get_data(chip);
	struct virtio_vfio_gpio_dir_output_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PINCTRL,
			.hdr.req_type = VIRTIO_VFIO_REQ_GPIO_DIR_OUT,
			.hdr.req_len = 2 * sizeof(uint64_t),
			.offset = offset,
			.val = value,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	return WARN_ON(virtio_transport_send_req_sync(vpctrl->virtio_trans, &msg,
						      sizeof(msg)));
}

static int virtio_gpio_get_direction(struct gpio_chip *chip, unsigned int offset)
{
	struct vfio_pinctrl_dev *vpctrl = gpiochip_get_data(chip);
	struct virtio_vfio_pinctrl_dir_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PINCTRL,
			.hdr.req_type = VIRTIO_VFIO_REQ_GPIO_GET_DIR,
			.hdr.req_len = sizeof(uint64_t),
			.offset = offset,
			.hdr.resp_len = sizeof(uint64_t) +
					sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(vpctrl->virtio_trans, &msg,
					       sizeof(msg)));
	return msg.dir;
}

static int virtio_gpio_get(struct gpio_chip *chip, unsigned offset)
{
	struct vfio_pinctrl_dev *vpctrl = gpiochip_get_data(chip);
	struct virtio_vfio_pinctrl_val_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PINCTRL,
			.hdr.req_type = VIRTIO_VFIO_REQ_GPIO_GET_VAL,
			.hdr.req_len = sizeof(uint64_t),
			.offset = offset,
			.hdr.resp_len = sizeof(uint64_t) +
					sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(vpctrl->virtio_trans, &msg,
					       sizeof(msg)));
	return msg.val;
}

static void virtio_gpio_set(struct gpio_chip *chip, unsigned offset, int value)
{
	struct vfio_pinctrl_dev *vpctrl = gpiochip_get_data(chip);
	struct virtio_vfio_pinctrl_val_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PINCTRL,
			.hdr.req_type = VIRTIO_VFIO_REQ_GPIO_SET_VAL,
			.hdr.req_len = 2 * sizeof(uint64_t),
			.offset = offset,
			.val = value,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(vpctrl->virtio_trans, &msg,
					       sizeof(msg)));
}

static int virtio_gpio_probe(struct vfio_pinctrl_dev *vpinctrl)
{
	struct gpio_chip *chip = &vpinctrl->chip;
	struct device *dev = vpinctrl->dev;
	int ret;
	struct virtio_vfio_pinctrl_get_descs_msg msg = {
		.hdr.dev_type = VIRTIO_ID_PINCTRL,
		.hdr.req_type = VIRTIO_VFIO_REQ_GPIO_GET_NR_DESC,
		.hdr.req_len = 0,
		.hdr.resp_len = sizeof(uint64_t) +
				sizeof(struct virtio_vfio_resp_status),
	};

	ret = virtio_transport_send_req_sync(vpinctrl->virtio_trans, &msg,
					     sizeof(msg));
	if (ret) {
		dev_err(dev, "Failed to get GPIO number of desc (err = %d)\n", ret);
		return ret;
	}

	chip->base = -1;
	chip->ngpio = msg.nr_desc;
	chip->label = dev_name(dev);
	chip->parent = dev;
	chip->owner = THIS_MODULE;
	chip->of_node = dev->of_node;

	chip->direction_input  = virtio_gpio_direction_input;
	chip->direction_output = virtio_gpio_direction_output;
	chip->get_direction    = virtio_gpio_get_direction;
	chip->get              = virtio_gpio_get;
	chip->set              = virtio_gpio_set;

	ret = gpiochip_add_data(&vpinctrl->chip, vpinctrl);
	if (ret) {
		dev_err(dev, "Failed register gpiochip\n");
		return ret;
	}

	/*
	 * For DeviceTree-supported systems, the gpio core checks the
	 * pinctrl's device node for the "gpio-ranges" property.
	 * If it is present, it takes care of adding the pin ranges
	 * for the driver. In this case the driver can skip ahead.
	 *
	 * In order to remain compatible with older, existing DeviceTree
	 * files which don't set the "gpio-ranges" property or systems that
	 * utilize ACPI the driver has to call gpiochip_add_pin_range().
	 */
	if (!of_property_read_bool(dev->of_node, "gpio-ranges")) {
		dev_err(dev, "no 'gpio-ranges' exist, adding default\n");
		ret = gpiochip_add_pin_range(chip, dev_name(dev), 0, 0,
					     chip->ngpio);
		if (ret) {
			dev_err(dev, "Failed to add pin range\n");
			gpiochip_remove(chip);
			return ret;
		}
	}

	return 0;
}

static void virtio_pinctrl_evt_handler(struct virtqueue *vq)
{
	struct vfio_pinctrl_dev *vpinctrl = vq->vdev->priv;
	struct scatterlist top_sg, bottom_sg;
	struct scatterlist *sg[2] = { &top_sg, &bottom_sg };
	struct virtio_vfio_pinctrl_event *evt;
	unsigned int len;
	uint32_t *status;
	uint8_t *buf;
	int ret;

	/* Event queue is still disabled */
	if (!vpinctrl)
		return;

	while ((buf = virtqueue_get_buf(vq, &len)) != NULL) {
		status = (uint32_t *)buf;
		evt = (struct virtio_vfio_pinctrl_event *)(buf + sizeof(uint32_t));

		ret = 0;
		*status = ret;

		sg_init_one(&top_sg, buf, sizeof(*status));
		sg_init_one(&bottom_sg, buf + sizeof(*status), sizeof(*evt));
		ret = virtqueue_add_sgs(vq, sg, 1, 1, buf, GFP_ATOMIC);
		if (ret)
			dev_err(vpinctrl->dev, "could not add event buffer\n");
	}

	virtqueue_kick(vq);
}

static int virtio_pinctrl_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct vfio_pinctrl_dev *vpinctrl;
	size_t evt_sz, evt_status_sz;
	int ret;

	dev_err(dev, "~~~~~~~~~~~~~~~ Driver probing\n");

	vpinctrl = devm_kzalloc(dev, sizeof(*vpinctrl), GFP_KERNEL);
	if (!vpinctrl)
		return -ENOMEM;

	vpinctrl->vdev = vdev;
	vpinctrl->dev = dev;
	evt_sz = sizeof(struct virtio_vfio_pinctrl_event);
	evt_status_sz = sizeof(uint32_t);
	vpinctrl->virtio_trans = virtio_transport_init(vdev,
						  virtio_pinctrl_evt_handler,
						  evt_sz, evt_status_sz);
	if (IS_ERR(vpinctrl->virtio_trans))
		return PTR_ERR(vpinctrl->virtio_trans);

	vpinctrl->desc.owner = THIS_MODULE;
	vpinctrl->desc.pctlops = &virtio_pinctrl_ops;
	vpinctrl->desc.confops = &virtio_pinconf_ops;
	vpinctrl->desc.name = dev_name(dev);
	vpinctrl->desc.pins = virtio_pinctrl_pins;
	vpinctrl->desc.npins = ARRAY_SIZE(virtio_pinctrl_pins);

	/*
	 * XXX: Hack to get pinctrl provider for virtio dev type which has no
	 * correlated of_node, therefore assign parent dev of_node.
	 */
	dev->of_node = dev->parent->of_node;
	vpinctrl->pctrl = devm_pinctrl_register(dev, &vpinctrl->desc, vpinctrl);
	if (IS_ERR(vpinctrl->pctrl)) {
		dev_err(dev, "Couldn't register pinctrl driver\n");
		ret = PTR_ERR(vpinctrl->pctrl);
		goto err;
	}

	ret = virtio_gpio_probe(vpinctrl);
	if (ret) {
		dev_err(dev, "Couldn't register GPIO chip\n");
		goto err;
	}

	vdev->priv = vpinctrl;
	return 0;
err:
	virtio_transport_deinit(vdev);
	return ret;
}

static void virtio_pinctrl_remove(struct virtio_device *vdev)
{
	virtio_transport_deinit(vdev);
}

static void virtio_pinctrl_config_changed(struct virtio_device *vdev)
{
	dev_dbg(&vdev->dev, "config changed\n");
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_PINCTRL, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
};

static struct virtio_driver virtio_pinctrl_drv = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.probe			= virtio_pinctrl_probe,
	.remove			= virtio_pinctrl_remove,
	.config_changed		= virtio_pinctrl_config_changed,
};

module_virtio_driver(virtio_pinctrl_drv);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Virtio pinctrl driver");
