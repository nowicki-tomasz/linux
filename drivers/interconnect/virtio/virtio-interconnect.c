// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 */

#include <linux/device.h>
#include <linux/interconnect.h>
#include <linux/interconnect-provider.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_transport.h>

#include <uapi/linux/virtio_vfio.h>

struct vinter_data {
	struct device		*dev;
	struct virtio_device	*vdev;
	struct virtio_trans	*virtio_trans;
	struct icc_provider	provider;
};

int vinter_set(struct icc_node *src, struct icc_node *dst)
{
	struct vinter_data *drvdata = src->data;
	struct device *dev = drvdata->dev;
	struct virtio_vfio_inter_set msg = {
			.hdr.dev_type = VIRTIO_ID_INTERCONNECT,
			.hdr.req_type = VIRTIO_VFIO_REQ_INTER_SET,
			.hdr.req_len = 2 * sizeof(__le64),
			.hdr.resp_len = sizeof(struct virtio_vfio_resp_status),
			.avg_bw = src->avg_bw,
			.peak_bw = src->peak_bw,
	};

	dev_err(dev, "~~~~~~~~ %s avg_bw %ld peak_bw %ld\n",
		__func__, (long)src->avg_bw, (long)src->peak_bw);

	return WARN_ON(virtio_transport_send_req_sync(drvdata->virtio_trans, &msg,
						      sizeof(msg)));
}

int vinter_aggregate(struct icc_node *node, u32 tag, u32 avg_bw,
		 u32 peak_bw, u32 *agg_avg, u32 *agg_peak)
{
	*agg_avg = avg_bw;
	*agg_peak = peak_bw;

	return 0;
}

static void vinter_evt_handler(struct virtqueue *vq)
{
}

static int vinter_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct device_node *np = dev->parent->of_node;
	struct vinter_data *drvdata;
	struct icc_onecell_data *data;
	struct icc_provider *provider;
	struct icc_node *node;
	size_t evt_sz, evt_status_sz, num_node = 2;
	static unsigned int instance;
	size_t i;
	int ret;

	drvdata = devm_kzalloc(dev, sizeof(*drvdata), GFP_KERNEL);
	if (!drvdata)
		return -ENOMEM;

	dev_err(dev, "~~~~~~~~ %s 2\n", __func__);

	drvdata->vdev = vdev;
	drvdata->dev = dev;
	evt_sz = sizeof(struct virtio_vfio_inter_event);
	evt_status_sz = sizeof(uint32_t);
	drvdata->virtio_trans = virtio_transport_init(vdev,
						  vinter_evt_handler,
						  evt_sz, evt_status_sz);
	if (IS_ERR(drvdata->virtio_trans))
		return PTR_ERR(drvdata->virtio_trans);

	data = devm_kzalloc(dev, struct_size(data, nodes, num_node), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	dev_err(dev, "~~~~~~~~ %s 2\n", __func__);

	provider = &drvdata->provider;
	provider->set = vinter_set;
	provider->aggregate = vinter_aggregate;
	provider->xlate = of_icc_xlate_onecell;
	INIT_LIST_HEAD(&provider->nodes);
	provider->data = data;

	/*
	 * XXX: Hack to get interconnect provider for virtio dev type which
	 * has no correlated of_node, therefore assign parent dev of_node.
	 */
	dev->of_node = dev->parent->of_node;
	provider->dev = dev;
	ret = icc_provider_add(provider);
	if (ret) {
		dev_err(dev, "error adding interconnect provider\n");
		return ret;
	}

	dev_err(dev, "~~~~~~~~ %s 2\n", __func__);

	/*
	 * Virtio interconnect restricts to propagate constrains as-is down
	 * to the host interconnect backend driver only. Therefore, we need only
	 * one node but since the DT binding requires pair of nodes we create
	 * two nodes within one provider and points to each other. In this setup
	 * one node has no meaning whatsoever.
	 */
	data->num_nodes = num_node;
	for (i = 0; i < data->num_nodes; i++) {
		node = icc_node_create(instance);
		if (IS_ERR(node)) {
			ret = PTR_ERR(node);
			goto err;
		}

		node->name = devm_kasprintf(dev, GFP_KERNEL, "%s-%u",
				np ? np->name : "virtio,interrconnect",
				instance);
		if (!node->name) {
			dev_err(dev, "Failed to allocate interconnect name\n");
			return -ENOMEM;
		}
		node->data = drvdata;

		icc_node_add(node, provider);
		icc_link_create(node, instance % 2 ? instance - 1 : instance + 1);
		data->nodes[i] = node;
		instance++;
	}
	vdev->priv = drvdata;
	return 0;
err:
	icc_nodes_remove(provider);
	icc_provider_del(provider);
	virtio_transport_deinit(vdev);
	return ret;
}

static void vinter_remove(struct virtio_device *vdev)
{
	struct vinter_data *drvdata = vdev->priv;

	icc_nodes_remove(&drvdata->provider);
	icc_provider_del(&drvdata->provider);
	virtio_transport_deinit(vdev);
}

static void vinter_config_changed(struct virtio_device *vdev)
{
	dev_dbg(&vdev->dev, "config changed\n");
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_INTERCONNECT, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
};

static struct virtio_driver vinter_drv = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.probe			= vinter_probe,
	.remove			= vinter_remove,
	.config_changed		= vinter_config_changed,
};

static int __init vinter_init(void)
{
	return register_virtio_driver(&vinter_drv);
}
subsys_initcall(vinter_init);

static void __exit vinter_cleanup(void)
{
	unregister_virtio_driver(&vinter_drv);
}
module_exit(vinter_cleanup);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Virtio interconnect driver");
