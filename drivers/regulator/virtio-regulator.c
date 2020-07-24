// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio driver for the paravirtualized VFIO platform device
 *
 * Copyright (C) 2020 Semihalf
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/of.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/of_regulator.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_transport.h>

#include <uapi/linux/virtio_vfio.h>

struct virtio_reg_data {
	struct device		*dev;
	struct virtio_device	*vdev;
	struct virtio_trans	*virtio_trans;
	struct regulator_desc	desc;
	struct regulator_dev	*rdev;
};

int virtio_regulator_enable(struct regulator_dev *rdev)
{
	struct virtio_reg_data *drvdata = rdev_get_drvdata(rdev);
	struct virtio_vfio_regulator_enable msg = {
			.hdr.dev_type = VIRTIO_ID_REGULATOR,
			.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_ENABLE,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	return WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
						      sizeof(msg)));
}

int virtio_regulator_disable(struct regulator_dev *rdev)
{
	struct virtio_reg_data *drvdata = rdev_get_drvdata(rdev);
	struct virtio_vfio_regulator_disable msg = {
			.hdr.dev_type = VIRTIO_ID_REGULATOR,
			.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_DISABLE,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	return WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
						      sizeof(msg)));
}

int virtio_regulator_is_enabled(struct regulator_dev *rdev)
{
	struct virtio_reg_data *drvdata = rdev_get_drvdata(rdev);
	struct virtio_vfio_regulator_is_enable msg = {
			.hdr.dev_type = VIRTIO_ID_REGULATOR,
			.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_IS_ENABLED,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(uint32_t) +
					sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
					       sizeof(msg)));

	return msg.is_enabled;
}


int virtio_regulator_get_current_limit(struct regulator_dev *rdev)
{
	struct virtio_reg_data *drvdata = rdev_get_drvdata(rdev);
	struct virtio_vfio_regulator_get_cur_limit msg = {
			.hdr.dev_type = VIRTIO_ID_REGULATOR,
			.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_GET_CUR_LIMIT,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(uint32_t) +
					sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
					      sizeof(msg)));
	return msg.cur_limit;
}

int virtio_regulator_set_current_limit(struct regulator_dev *rdev,
				       int min_uA, int max_uA)
{
	struct virtio_reg_data *drvdata = rdev_get_drvdata(rdev);
	struct virtio_vfio_regulator_set_cur_limit msg = {
			.hdr.dev_type = VIRTIO_ID_REGULATOR,
			.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_SET_CUR_LIMIT,
			.hdr.req_len = 2 * sizeof(uint32_t),
			.min_uA = min_uA,
			.max_uA = max_uA,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	return WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
						      sizeof(msg)));
}

int virtio_regulator_list_voltage(struct regulator_dev *rdev, unsigned selector)
{
	struct virtio_reg_data *drvdata = rdev_get_drvdata(rdev);
	struct virtio_vfio_regulator_list_voltage msg = {
			.hdr.dev_type = VIRTIO_ID_REGULATOR,
			.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_LIST_VOLTAGE,
			.hdr.req_len = sizeof(uint32_t),
			.selector = selector,
			.hdr.resp_len = sizeof(uint32_t) +
					sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
						      sizeof(msg)));
	return msg.vol;
}

int virtio_regulator_map_voltage(struct regulator_dev *rdev,
				 int min_uV, int max_uV)
{
	struct virtio_reg_data *drvdata = rdev_get_drvdata(rdev);
	struct virtio_vfio_regulator_map_voltage msg = {
			.hdr.dev_type = VIRTIO_ID_REGULATOR,
			.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_MAP_VOLTAGE,
			.hdr.req_len = 2 * sizeof(uint32_t),
			.min_uV = min_uV,
			.max_uV = max_uV,
			.hdr.resp_len = sizeof(uint32_t) +
					sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
						      sizeof(msg)));
	return msg.selector;
}

int virtio_regulator_get_voltage(struct regulator_dev *rdev)
{
	struct virtio_reg_data *drvdata = rdev_get_drvdata(rdev);
	struct virtio_vfio_regulator_get_voltage msg = {
			.hdr.dev_type = VIRTIO_ID_REGULATOR,
			.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_GET_VOLTAGE,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(uint32_t) +
					sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
						      sizeof(msg)));
	return msg.selector;
}

int virtio_regulator_set_voltage(struct regulator_dev *rdev,
				 int min_uV, int max_uV, unsigned *selector)
{
	struct virtio_reg_data *drvdata = rdev_get_drvdata(rdev);
	struct virtio_vfio_regulator_set_voltage msg = {
			.hdr.dev_type = VIRTIO_ID_REGULATOR,
			.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_SET_VOLTAGE,
			.hdr.req_len = sizeof(uint32_t),
			.min_uV = min_uV,
			.max_uV = max_uV,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};
	int ret;

	ret = WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
						      sizeof(msg)));
	*selector = msg.selector;
	return ret;
}


static struct regulator_ops virtio_regulator_ops = {
	.enable = virtio_regulator_enable,
	.disable = virtio_regulator_disable,
	.is_enabled = virtio_regulator_is_enabled,
	.get_current_limit = virtio_regulator_get_current_limit,
	.set_current_limit = virtio_regulator_set_current_limit,
	.list_voltage = virtio_regulator_list_voltage,
	.map_voltage = virtio_regulator_map_voltage,
	.get_voltage = virtio_regulator_get_voltage,
	.set_voltage = virtio_regulator_set_voltage, // rdev->constraints->uV_offset must == 0

};

static void virtio_regulator_evt_handler(struct virtqueue *vq)
{
	struct virtio_reg_data *drvdata = vq->vdev->priv;
	struct scatterlist top_sg, bottom_sg;
	struct scatterlist *sg[2] = { &top_sg, &bottom_sg };
	struct virtio_vfio_regulator_event *evt;
	unsigned int len;
//	struct clk *clk;
	uint32_t *status;
	uint8_t *buf;
	int ret;

	/* Event queue is still disabled */
	if (!drvdata)
		return;

//	clk = drvdata->hw.clk;
	while ((buf = virtqueue_get_buf(vq, &len)) != NULL) {
		status = (uint32_t *)buf;
		evt = (struct virtio_vfio_regulator_event *)(buf + sizeof(uint32_t));

		ret = 0;
//		ret = clk_notify(clk, evt->msg, evt->old_rate, evt->new_rate);
//		if (ret & NOTIFY_STOP_MASK) {
//			dev_err(drvdata->dev,
//				"%s: clk notifier callback aborted (err = %d)\n",
//				__func__, ret);
//		}
		*status = ret;

		sg_init_one(&top_sg, buf, sizeof(*status));
		sg_init_one(&bottom_sg, buf + sizeof(*status), sizeof(*evt));
		ret = virtqueue_add_sgs(vq, sg, 1, 1, buf, GFP_ATOMIC);
		if (ret)
			dev_err(drvdata->dev, "could not add event buffer\n");
	}

	virtqueue_kick(vq);
}

static int virtio_regulator_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct device_node *node = dev->of_node;
	struct virtio_reg_data *drvdata;
	struct regulator_config cfg = { };
	size_t evt_sz, evt_status_sz;
	unsigned n_voltages, type;
	static int instance;
	int ret;
	struct virtio_vfio_regulator_type msg_type = {
		.hdr.dev_type = VIRTIO_ID_REGULATOR,
		.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_GET_TYPE,
		.hdr.resp_len = sizeof(type) +
				sizeof(struct virtio_vfio_resp_status),
	};
	struct virtio_vfio_regulator_n_voltages msg_n_voltages = {
		.hdr.dev_type = VIRTIO_ID_REGULATOR,
		.hdr.req_type = VIRTIO_VFIO_REQ_REGULATOR_GET_N_VOLTAGES,
		.hdr.resp_len = sizeof(n_voltages) +
				sizeof(struct virtio_vfio_resp_status),
	};

	drvdata = devm_kzalloc(dev, sizeof(*drvdata), GFP_KERNEL);
	if (!drvdata)
		return -ENOMEM;

	drvdata->vdev = vdev;
	drvdata->dev = dev;
	evt_sz = sizeof(struct virtio_vfio_regulator_event);
	evt_status_sz = sizeof(uint32_t);
	drvdata->virtio_trans = virtio_transport_init(vdev,
						  virtio_regulator_evt_handler,
						  evt_sz, evt_status_sz);
	if (IS_ERR(drvdata->virtio_trans))
		return PTR_ERR(drvdata->virtio_trans);

	drvdata->desc.name = devm_kasprintf(dev, GFP_KERNEL, "%s-%d",
					node ? node->name : "virtio,regulator",
					instance++);
	if (drvdata->desc.name == NULL) {
		dev_err(dev, "Failed to allocate supply name\n");
		return -ENOMEM;
	}

	drvdata->desc.owner = THIS_MODULE;
	drvdata->desc.ops = &virtio_regulator_ops;

	ret = virtio_transport_send_req_sync(drvdata->virtio_trans, &msg_type,
					     sizeof(msg_type));
	if (ret) {
		dev_err(dev, "Failed to get regulator number of voltages (err = %d)\n",
			ret);
		goto err;
	}
	drvdata->desc.type = msg_type.type;

	ret = virtio_transport_send_req_sync(drvdata->virtio_trans, &msg_n_voltages,
					     sizeof(msg_n_voltages));
	if (ret) {
		dev_err(dev, "Failed to get regulator number of voltages (err = %d)\n",
			ret);
		goto err;
	}
	drvdata->desc.n_voltages = msg_n_voltages.n_voltages;

	cfg.dev = dev;
	cfg.driver_data = drvdata;
	cfg.of_node = node;

	drvdata->rdev = devm_regulator_register(dev, &drvdata->desc, &cfg);
	if (IS_ERR(drvdata->dev)) {
		ret = PTR_ERR(drvdata->dev);
		dev_err(dev, "Failed to register regulator: %d\n", ret);
		return ret;
	}
	vdev->priv = drvdata;

	dev_err(dev, "%s probed successfully\n", drvdata->desc.name);
	return 0;
err:
	virtio_transport_deinit(vdev);
	return ret;
}

static void virtio_regulator_remove(struct virtio_device *vdev)
{
	virtio_transport_deinit(vdev);
}

static void virtio_regulator_config_changed(struct virtio_device *vdev)
{
	dev_dbg(&vdev->dev, "config changed\n");
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_REGULATOR, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
};

static struct virtio_driver virtio_regulator_drv = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.probe			= virtio_regulator_probe,
	.remove			= virtio_regulator_remove,
	.config_changed		= virtio_regulator_config_changed,
};

module_virtio_driver(virtio_regulator_drv);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Virtio regulator driver");
