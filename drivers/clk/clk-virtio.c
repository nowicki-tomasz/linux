// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio driver for the paravirtualized VFIO platform device
 *
 * Copyright (C) 2020 Semihalf
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_transport.h>
#include <uapi/linux/virtio_vfio.h>

struct vfio_clk_dev {
	struct device		*dev;
	struct virtio_device	*vdev;
	struct virtio_trans	*virtio_trans;
	struct clk_hw		hw;
};

#define to_virtio_clk(_hw) container_of(_hw, struct vfio_clk_dev, hw)

static int virtio_clk_prepare(struct clk_hw *hw)
{
	struct vfio_clk_dev *clk = to_virtio_clk(hw);
	struct virtio_vfio_clk_prepare msg = {
			.hdr.dev_type = VIRTIO_ID_CLK,
			.hdr.req_type = VIRTIO_VFIO_REQ_CLK_PREPARE,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	return WARN_ON(virtio_transport_send_req_sync(clk->virtio_trans, &msg,
						      sizeof(msg)));
}

static void virtio_clk_unprepare(struct clk_hw *hw)
{
	struct vfio_clk_dev *clk = to_virtio_clk(hw);
	struct virtio_vfio_clk_unprepare msg = {
			.hdr.dev_type = VIRTIO_ID_CLK,
			.hdr.req_type = VIRTIO_VFIO_REQ_CLK_UNPREPARE,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(clk->virtio_trans, &msg,
					       sizeof(msg)));
}

static int virtio_clk_enable(struct clk_hw *hw)
{
	struct vfio_clk_dev *clk = to_virtio_clk(hw);
	struct virtio_vfio_clk_enable msg = {
			.hdr.dev_type = VIRTIO_ID_CLK,
			.hdr.req_type = VIRTIO_VFIO_REQ_CLK_ENABLE,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	return WARN_ON(virtio_transport_send_req_sync(clk->virtio_trans, &msg,
						      sizeof(msg)));
}

static void virtio_clk_disable(struct clk_hw *hw)
{
	struct vfio_clk_dev *clk = to_virtio_clk(hw);
	struct virtio_vfio_clk_disable msg = {
			.hdr.dev_type = VIRTIO_ID_CLK,
			.hdr.req_type = VIRTIO_VFIO_REQ_CLK_DISABLE,
			.hdr.req_len = 0,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	WARN_ON(virtio_transport_send_req_sync(clk->virtio_trans, &msg,
					       sizeof(msg)));
}

static unsigned long virtio_clk_recalc_rate(struct clk_hw *hw,
					    unsigned long parent_rate)
{
	struct vfio_clk_dev *clk = to_virtio_clk(hw);
	struct virtio_vfio_clk_rate msg = {
			.hdr.dev_type = VIRTIO_ID_CLK,
			.hdr.req_type = VIRTIO_VFIO_REQ_CLK_RECALC_RATE,
			.hdr.req_len = sizeof(parent_rate),
			.hdr.resp_len = sizeof(parent_rate) +
					sizeof(struct virtio_vfio_resp_status),
			.parent_rate = parent_rate,
	};

	WARN_ON(virtio_transport_send_req_sync(clk->virtio_trans, &msg,
					       sizeof(msg)));
	return msg.rate;
}

int virtio_clk_set_rate(struct clk_hw *hw, unsigned long rate,
			unsigned long parent_rate)
{
	struct vfio_clk_dev *clk = to_virtio_clk(hw);
	struct virtio_vfio_clk_rate msg = {
			.hdr.dev_type = VIRTIO_ID_CLK,
			.hdr.req_type = VIRTIO_VFIO_REQ_CLK_SET_RATE,
			.hdr.req_len = 2 * sizeof(parent_rate),
			.parent_rate = parent_rate,
			.rate = rate,
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
	};

	return virtio_transport_send_req_sync(clk->virtio_trans, &msg,
					      sizeof(msg));
}

static long virtio_clk_round_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long *parent_rate)
{
	struct vfio_clk_dev *clk = to_virtio_clk(hw);
	struct virtio_vfio_clk_round_rate msg = {
			.hdr.dev_type = VIRTIO_ID_CLK,
			.hdr.req_type = VIRTIO_VFIO_REQ_CLK_ROUND_RATE,
			.hdr.req_len = sizeof(rate),
			.hdr.resp_len = sizeof(rate) +
					sizeof(struct virtio_vfio_resp_status),
			.rate = rate,
	};

	WARN_ON(virtio_transport_send_req_sync(clk->virtio_trans, &msg,
					       sizeof(msg)));
	return msg.rate_round;
}

static const struct clk_ops virtio_clk_ops = {
	.prepare	= virtio_clk_prepare,
	.unprepare	= virtio_clk_unprepare,
	.enable		= virtio_clk_enable,
	.disable	= virtio_clk_disable,
	.recalc_rate	= virtio_clk_recalc_rate,
	.set_rate	= virtio_clk_set_rate,
	.round_rate	= virtio_clk_round_rate,
};

/*
 * In order to have synchronous host to guest event notification
 * we ever expect to manage only one descriptor at a time which means that
 * guest prepares only one descriptor upfront and refill when receive an event.
 * 1. Guest push one desc which conveys in and out buf
 * 2. Host fills event info into the in buf and sends to guest
 * 3. Guest consumes event and refill queue with new desc
 * 4. At the same time guest updates prev operation status into the out buffer
 * 5. Host polls for available desc and read the status from out buf
 * 6. The same desc and its in buf  will be used for subsequent event
 */
static void virtio_clk_evt_handler(struct virtqueue *vq)
{
	struct vfio_clk_dev *clk_dev = vq->vdev->priv;
	struct scatterlist top_sg, bottom_sg;
	struct scatterlist *sg[2] = { &top_sg, &bottom_sg };
	struct virtio_vfio_clk_event *evt;
	unsigned int len;
	struct clk *clk;
	uint32_t *status;
	uint8_t *buf;
	int ret;

	/* Event queue is still disabled */
	if (!clk_dev)
		return;

	clk = clk_dev->hw.clk;
	while ((buf = virtqueue_get_buf(vq, &len)) != NULL) {
		status = (uint32_t *)buf;
		evt = (struct virtio_vfio_clk_event *)(buf + sizeof(uint32_t));

		ret = clk_notify(clk, evt->msg, evt->old_rate, evt->new_rate);
		if (ret & NOTIFY_STOP_MASK) {
			dev_err(clk_dev->dev,
				"%s: clk notifier callback aborted (err = %d)\n",
				__func__, ret);
		}
		*status = ret;

		sg_init_one(&top_sg, buf, sizeof(*status));
		sg_init_one(&bottom_sg, buf + sizeof(*status), sizeof(*evt));
		ret = virtqueue_add_sgs(vq, sg, 1, 1, buf, GFP_ATOMIC);
		if (ret)
			dev_err(clk_dev->dev, "could not add event buffer\n");
	}

	virtqueue_kick(vq);
}

static int virtio_clk_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct device_node *node = dev->parent->of_node;
	struct clk_init_data init = { };
	struct vfio_clk_dev *clk;
	static int instance;
	struct clk_hw *hw;
	uint64_t flags;
	size_t evt_sz, evt_status_sz;
	int ret;
	struct virtio_vfio_clk_flags msg = {
		.hdr.dev_type = VIRTIO_ID_CLK,
		.hdr.req_type = VIRTIO_VFIO_REQ_CLK_GET_FLAGS,
		.hdr.resp_len = sizeof(flags) +
				sizeof(struct virtio_vfio_resp_status),
	};

	clk = devm_kzalloc(dev, sizeof(*clk), GFP_KERNEL);
	if (!clk)
		return -ENOMEM;

	clk->vdev = vdev;
	clk->dev = dev;
	evt_sz = sizeof(struct virtio_vfio_clk_event);
	evt_status_sz = sizeof(uint32_t);
	clk->virtio_trans = virtio_transport_init(vdev,
						  virtio_clk_evt_handler,
						  evt_sz, evt_status_sz);
	if (IS_ERR(clk->virtio_trans))
		return PTR_ERR(clk->virtio_trans);

	ret = virtio_transport_send_req_sync(clk->virtio_trans, &msg,
					     sizeof(msg));
	if (ret) {
		dev_err(dev, "Failed to get clock's flag (err = %d)\n", ret);
		goto err;
	}

	init.name = devm_kasprintf(dev, GFP_KERNEL, "%s-%d",
				   node ? node->name : "virtio,clk",
				   instance++);
	init.ops = &virtio_clk_ops;
	init.flags = msg.flags;
	init.flags &= ~CLK_SET_RATE_PARENT;
	/*
	 * Parent manipulation and reparent operation is not supported.
	 * Instead, forward all requests to Virtio backend and let it make
	 * decisions.
	 */
	init.num_parents = 0;
	clk->hw.init = &init;

	hw = &clk->hw;
	ret = devm_clk_hw_register(dev, hw);
	if (ret) {
		dev_err(dev, "Failed to register clock (err = %d)\n", ret);
		goto err;
	}

	ret = devm_of_clk_add_hw_provider(dev, of_clk_hw_simple_get, hw);
	if (ret) {
		dev_err(dev, "Failed to add clock provider (err = %d)\n", ret);
		goto err;
	}

	vdev->priv = clk;
	return 0;
err:
	virtio_transport_deinit(vdev);
	return ret;
}

static void virtio_clk_remove(struct virtio_device *vdev)
{
	virtio_transport_deinit(vdev);
}

static void virtio_clk_config_changed(struct virtio_device *vdev)
{
	dev_dbg(&vdev->dev, "config changed\n");
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_CLK, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
};

static struct virtio_driver virtio_clk_drv = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.probe			= virtio_clk_probe,
	.remove			= virtio_clk_remove,
	.config_changed		= virtio_clk_config_changed,
};

module_virtio_driver(virtio_clk_drv);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Virtio clock driver");
