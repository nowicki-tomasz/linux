// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio driver for the paravirtualized VFIO platform device
 *
 * Copyright (C) 2020 Semihalf
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/phy/phy.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_transport.h>
#include <uapi/linux/virtio_vfio.h>

struct vfio_phy_dev {
	struct device		*dev;
	struct virtio_device	*vdev;
	struct virtio_trans	*virtio_trans;
	struct phy		*phy;
};

static int virtio_phy_init(struct phy *phy)
{
	struct vfio_phy_dev *vphy = phy_get_drvdata(phy);
	struct virtio_vfio_phy_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PHY,
			.hdr.req_type = VIRTIO_VFIO_REQ_PHY_INIT,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	dev_err(vphy->dev, "~~~~~~~~ %s phy name %s\n",
			__func__, dev_name(&phy->dev));

	return WARN_ON(virtio_transport_send_req_sync(vphy->virtio_trans, &msg,
						      sizeof(msg)));
}

static int virtio_phy_exit(struct phy *phy)
{
	struct vfio_phy_dev *vphy = phy_get_drvdata(phy);
	struct virtio_vfio_phy_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PHY,
			.hdr.req_type = VIRTIO_VFIO_REQ_PHY_EXIT,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	dev_err(vphy->dev, "~~~~~~~~ %s phy name %s\n",
			__func__, dev_name(&phy->dev));

	return WARN_ON(virtio_transport_send_req_sync(vphy->virtio_trans, &msg,
						      sizeof(msg)));
}

static int virtio_phy_set_mode(struct phy *phy,
			      enum phy_mode mode, int submode)
{
	struct vfio_phy_dev *vphy = phy_get_drvdata(phy);
	struct virtio_vfio_phy_mode msg = {
			.hdr.dev_type = VIRTIO_ID_PHY,
			.hdr.req_type = VIRTIO_VFIO_REQ_PHY_SET_MODE,
			.hdr.req_len = 2 * sizeof(uint64_t),
			.mode = mode,
			.submode = submode,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	dev_err(vphy->dev, "~~~~~~~~ %s phy name %s\n",
			__func__, dev_name(&phy->dev));

	return WARN_ON(virtio_transport_send_req_sync(vphy->virtio_trans, &msg,
						      sizeof(msg)));
}

static int virtio_phy_power_on(struct phy *phy)
{
	struct vfio_phy_dev *vphy = phy_get_drvdata(phy);
	struct virtio_vfio_phy_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PHY,
			.hdr.req_type = VIRTIO_VFIO_REQ_PHY_POWER_ON,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	dev_err(vphy->dev, "~~~~~~~~ %s phy name %s\n",
			__func__, dev_name(&phy->dev));

	return WARN_ON(virtio_transport_send_req_sync(vphy->virtio_trans, &msg,
						      sizeof(msg)));
}

static int virtio_phy_power_off(struct phy *phy)
{
	struct vfio_phy_dev *vphy = phy_get_drvdata(phy);
	struct virtio_vfio_phy_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PHY,
			.hdr.req_type = VIRTIO_VFIO_REQ_PHY_POWER_OFF,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	dev_err(vphy->dev, "~~~~~~~~ %s phy name %s\n",
			__func__, dev_name(&phy->dev));

	return WARN_ON(virtio_transport_send_req_sync(vphy->virtio_trans, &msg,
						      sizeof(msg)));
}

static int virtio_phy_reset(struct phy *phy)
{
	struct vfio_phy_dev *vphy = phy_get_drvdata(phy);
	struct virtio_vfio_phy_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PHY,
			.hdr.req_type = VIRTIO_VFIO_REQ_PHY_RESET,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	dev_err(vphy->dev, "~~~~~~~~ %s phy name %s\n",
			__func__, dev_name(&phy->dev));

	return WARN_ON(virtio_transport_send_req_sync(vphy->virtio_trans, &msg,
						      sizeof(msg)));
}

static int virtio_phy_calibrate(struct phy *phy)
{
	struct vfio_phy_dev *vphy = phy_get_drvdata(phy);
	struct virtio_vfio_phy_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PHY,
			.hdr.req_type = VIRTIO_VFIO_REQ_PHY_CALIBRATE,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	dev_err(vphy->dev, "~~~~~~~~ %s phy name %s\n",
			__func__, dev_name(&phy->dev));

	return WARN_ON(virtio_transport_send_req_sync(vphy->virtio_trans, &msg,
						      sizeof(msg)));
}

static void virtio_phy_release(struct phy *phy)
{
	struct vfio_phy_dev *vphy = phy_get_drvdata(phy);
	struct virtio_vfio_phy_msg msg = {
			.hdr.dev_type = VIRTIO_ID_PHY,
			.hdr.req_type = VIRTIO_VFIO_REQ_PHY_RELEASE,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	dev_err(vphy->dev, "~~~~~~~~ %s phy name %s\n",
			__func__, dev_name(&phy->dev));

	WARN_ON(virtio_transport_send_req_sync(vphy->virtio_trans, &msg,
					       sizeof(msg)));
}

static const struct phy_ops virtio_phy_gen_ops = {
	.init		= virtio_phy_init,
	.exit		= virtio_phy_exit,
	.set_mode	= virtio_phy_set_mode,
	.power_on	= virtio_phy_power_on,
	.power_off	= virtio_phy_power_off,
	.reset		= virtio_phy_reset,
	.calibrate	= virtio_phy_calibrate,
	.release	= virtio_phy_release,
	.owner		= THIS_MODULE,
};

static void virtio_phy_evt_handler(struct virtqueue *vq)
{
	struct vfio_phy_dev *vphy = vq->vdev->priv;
	struct scatterlist top_sg, bottom_sg;
	struct scatterlist *sg[2] = { &top_sg, &bottom_sg };
	struct virtio_vfio_phy_event *evt;
	unsigned int len;
	uint32_t *status;
	uint8_t *buf;
	int ret;

	/* Event queue is still disabled */
	if (!vphy)
		return;

	while ((buf = virtqueue_get_buf(vq, &len)) != NULL) {
		status = (uint32_t *)buf;
		evt = (struct virtio_vfio_phy_event *)(buf + sizeof(uint32_t));

		ret = 0;
		*status = ret;

		sg_init_one(&top_sg, buf, sizeof(*status));
		sg_init_one(&bottom_sg, buf + sizeof(*status), sizeof(*evt));
		ret = virtqueue_add_sgs(vq, sg, 1, 1, buf, GFP_ATOMIC);
		if (ret)
			dev_err(vphy->dev, "could not add event buffer\n");
	}

	virtqueue_kick(vq);
}

static int virtio_phy_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct vfio_phy_dev *vphy;
	struct phy *generic_phy;
	struct phy_provider *phy_provider;
	size_t evt_sz, evt_status_sz;
	int ret;

	dev_err(dev, "~~~~~~~~~~~~~~~ Driver probing\n");

	vphy = devm_kzalloc(dev, sizeof(*vphy), GFP_KERNEL);
	if (!vphy)
		return -ENOMEM;

	vphy->vdev = vdev;
	vphy->dev = dev;
	evt_sz = sizeof(struct virtio_vfio_phy_event);
	evt_status_sz = sizeof(uint32_t);
	vphy->virtio_trans = virtio_transport_init(vdev,
						  virtio_phy_evt_handler,
						  evt_sz, evt_status_sz);
	if (IS_ERR(vphy->virtio_trans))
		return PTR_ERR(vphy->virtio_trans);

	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);
	/*
	 * Prevent runtime pm from being ON by default. Users can enable
	 * it using power/control in sysfs.
	 */
	pm_runtime_forbid(dev);

	/*
	 * XXX: Hack to get phy provider for virtio dev type which has no
	 * correlated of_node, therefore assign parent dev of_node.
	 */
	dev->of_node = dev->parent->of_node;
	generic_phy = devm_phy_create(dev, NULL, &virtio_phy_gen_ops);
	if (IS_ERR(generic_phy)) {
		ret = PTR_ERR(generic_phy);
		dev_err(dev, "failed to create phy, %d\n", ret);
		goto err;
	}
	vphy->phy = generic_phy;

	phy_set_drvdata(generic_phy, vphy);

	phy_provider = devm_of_phy_provider_register(dev, of_phy_simple_xlate);
	if (!IS_ERR(phy_provider))
		dev_err(dev, "Registered virtio phy\n");
	else {
		ret = PTR_ERR_OR_ZERO(phy_provider);
		dev_err(dev, "failed to regoster provider, %d\n", ret);
		goto err;
	}

	vdev->priv = vphy;
	return 0;
err:
	pm_runtime_disable(dev);
	virtio_transport_deinit(vdev);
	return ret;
}

static void virtio_phy_remove(struct virtio_device *vdev)
{
	virtio_transport_deinit(vdev);
}

static void virtio_phy_config_changed(struct virtio_device *vdev)
{
	dev_dbg(&vdev->dev, "config changed\n");
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_PHY, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
};

static struct virtio_driver virtio_phy_drv = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.probe			= virtio_phy_probe,
	.remove			= virtio_phy_remove,
	.config_changed		= virtio_phy_config_changed,
};

module_virtio_driver(virtio_phy_drv);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Virtio phy driver");
