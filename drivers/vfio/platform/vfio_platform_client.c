// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio driver for the paravirtualized VFIO platform device
 *
 * Copyright (C) 2020 Semihalf Limited
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/amba/bus.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/freezer.h>
#include <linux/interval_tree.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/wait.h>

#include <uapi/linux/virtio_vfio.h>

#define VIRTIO_VFIO_CLIENT_REQUEST_VQ		0
#define VIRTIO_VFIO_CLIENT_EVENT_VQ		1
#define VIRTIO_VFIO_CLIENT_NR_VQS		2

struct vfio_client_dev {
	struct device			*dev;
	struct virtio_device		*vdev;

	struct virtqueue		*vqs[VIRTIO_VFIO_CLIENT_NR_VQS];
	spinlock_t			request_lock;
	struct list_head		requests;
	void				*evts;
};

struct vfio_client_request {
	struct list_head		list;
	void				*writeback;
	unsigned int			write_offset;
	unsigned int			len;
	char				buf[];
};

static int virtvfio_client_get_req_errno(void *buf, size_t len)
{
	struct virtio_vfio_req_tail *tail = buf + len - sizeof(*tail);

	switch (tail->status) {
	case VIRTIO_VFIO_S_OK:
		return 0;
	case VIRTIO_VFIO_S_UNSUPP:
		return -ENOSYS;
	case VIRTIO_VFIO_S_INVAL:
		return -EINVAL;
	case VIRTIO_VFIO_S_RANGE:
		return -ERANGE;
	case VIRTIO_VFIO_S_NOENT:
		return -ENOENT;
	case VIRTIO_VFIO_S_FAULT:
		return -EFAULT;
	case VIRTIO_VFIO_S_NOMEM:
		return -ENOMEM;
	case VIRTIO_VFIO_S_IOERR:
	case VIRTIO_VFIO_S_DEVERR:
	default:
		return -EIO;
	}
}

static void virtvfio_client_set_req_status(void *buf, size_t len, int status)
{
	struct virtio_vfio_req_tail *tail = buf + len - sizeof(*tail);

	tail->status = status;
}

static off_t virtvfio_client_get_write_desc_offset(struct vfio_client_dev *vfio_client,
					  struct virtio_vfio_req_hdr *req,
					  size_t len)
{
	size_t tail_size = sizeof(struct virtio_vfio_req_tail);

	if (req->dev_type == VIRTIO_IOMMU_T_PROBE)
		return len - vfio_client->probe_size - tail_size;

	return len - tail_size;
}

/*
 * __virtvfio_client_sync_req - Complete all in-flight requests
 *
 * Wait for all added requests to complete. When this function returns, all
 * requests that were in-flight at the time of the call have completed.
 */
static int __virtvfio_client_sync_req(struct vfio_client_dev *vfio_client)
{
	int ret = 0;
	unsigned int len;
	size_t write_len;
	struct vfio_client_request *req;
	struct virtqueue *vq = vfio_client->vqs[VIRTIO_VFIO_CLIENT_REQUEST_VQ];

	assert_spin_locked(&vfio_client->request_lock);

	virtqueue_kick(vq);

	while (!list_empty(&vfio_client->requests)) {
		len = 0;
		req = virtqueue_get_buf(vq, &len);
		if (!req)
			continue;

		if (!len)
			virtvfio_client_set_req_status(req->buf, req->len,
					      VIRTIO_VFIO_S_IOERR);

		write_len = req->len - req->write_offset;
		if (req->writeback && len == write_len)
			memcpy(req->writeback, req->buf + req->write_offset,
			       write_len);

		list_del(&req->list);
		kfree(req);
	}

	return ret;
}

int virtvfio_client_sync_req(struct vfio_client_dev *vfio_client)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&vfio_client->request_lock, flags);
	ret = __virtvfio_client_sync_req(vfio_client);
	if (ret)
		dev_dbg(vfio_client->dev, "could not sync requests (%d)\n", ret);
	spin_unlock_irqrestore(&vfio_client->request_lock, flags);

	return ret;
}

/*
 * __virtvfio_client_add_req - Add one request to the queue
 * @buf: pointer to the request buffer
 * @len: length of the request buffer
 * @writeback: copy data back to the buffer when the request completes.
 *
 * Add a request to the queue. Only synchronize the queue if it's already full.
 * Otherwise don't kick the queue nor wait for requests to complete.
 *
 * When @writeback is true, data written by the device, including the request
 * status, is copied into @buf after the request completes. This is unsafe if
 * the caller allocates @buf on stack and drops the lock between add_req() and
 * sync_req().
 *
 * Return 0 if the request was successfully added to the queue.
 */
static int __virtvfio_client_add_req(struct vfio_client_dev *vfio_client,
				     void *buf, size_t len, bool writeback)
{
	int ret;
	off_t write_offset;
	struct vfio_client_request *req;
	struct scatterlist top_sg, bottom_sg;
	struct scatterlist *sg[2] = { &top_sg, &bottom_sg };
	struct virtqueue *vq = vfio_client->vqs[VIRTIO_VFIO_CLIENT_REQUEST_VQ];

	assert_spin_locked(&vfio_client->request_lock);

	write_offset = virtvfio_client_get_write_desc_offset(vfio_client, buf, len);
	if (write_offset <= 0)
		return -EINVAL;

	req = kzalloc(sizeof(*req) + len, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	req->len = len;
	if (writeback) {
		req->writeback = buf + write_offset;
		req->write_offset = write_offset;
	}
	memcpy(&req->buf, buf, write_offset);

	sg_init_one(&top_sg, req->buf, write_offset);
	sg_init_one(&bottom_sg, req->buf + write_offset, len - write_offset);

	ret = virtqueue_add_sgs(vq, sg, 1, 1, req, GFP_ATOMIC);
	if (ret == -ENOSPC) {
		/* If the queue is full, sync and retry */
		if (!__virtvfio_client_sync_req(vfio_client))
			ret = virtqueue_add_sgs(vq, sg, 1, 1, req, GFP_ATOMIC);
	}
	if (ret)
		goto err_free;

	list_add_tail(&req->list, &vfio_client->requests);
	return 0;

err_free:
	kfree(req);
	return ret;
}

int virtvfio_client_add_req(struct vfio_client_dev *vfio_client,
				   void *buf, size_t len)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&vfio_client->request_lock, flags);
	ret = __virtvfio_client_add_req(vfio_client, buf, len, false);
	if (ret)
		dev_dbg(vfio_client->dev, "could not add request: %d\n", ret);
	spin_unlock_irqrestore(&vfio_client->request_lock, flags);

	return ret;
}

/*
 * Send a request and wait for it to complete. Return the request status (as an
 * errno)
 */
int virtvfio_client_send_req_sync(struct vfio_client_dev *vfio_client,
					 void *buf, size_t len)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&vfio_client->request_lock, flags);

	ret = __virtvfio_client_add_req(vfio_client, buf, len, true);
	if (ret) {
		dev_dbg(vfio_client->dev, "could not add request (%d)\n", ret);
		goto out_unlock;
	}

	ret = __virtvfio_client_sync_req(vfio_client);
	if (ret) {
		dev_dbg(vfio_client->dev, "could not sync requests (%d)\n", ret);
		/* Fall-through (get the actual request status) */
	}

	ret = virtvfio_client_get_req_errno(buf, len);
out_unlock:
	spin_unlock_irqrestore(&vfio_client->request_lock, flags);
	return ret;
}

static void virtvfio_client_event_handler(struct virtqueue *vq)
{
	pr_err("got unsupported event");
}

static int virtvfio_client_init_vqs(struct vfio_client_dev *vfio_client)
{
	struct virtio_device *vdev = dev_to_virtio(vfio_client->dev);
	const char *names[] = { "request", "event" };
	vq_callback_t *callbacks[] = {
		NULL, /* No async requests */
		virtvfio_client_event_handler,
	};

	return virtio_find_vqs(vdev, VIRTIO_VFIO_CLIENT_NR_VQS,
			       vfio_client->vqs, callbacks, names, NULL);
}

static int virtvfio_client_fill_evtq(struct vfio_client_dev *viommu)
{
	int i, ret;
	struct scatterlist sg[1];
	struct viommu_event *evts;
	struct virtqueue *vq = viommu->vqs[VIRTIO_VFIO_CLIENT_EVENT_VQ];
	size_t nr_evts = vq->num_free;

	viommu->evts = evts = devm_kmalloc_array(viommu->dev, nr_evts,
						 sizeof(*evts), GFP_KERNEL);
	if (!evts)
		return -ENOMEM;

	for (i = 0; i < nr_evts; i++) {
		sg_init_one(sg, &evts[i], sizeof(*evts));
		ret = virtqueue_add_inbuf(vq, sg, 1, &evts[i], GFP_KERNEL);
		if (ret)
			return ret;
	}

	return 0;
}

static int virtvfio_client_probe(struct virtio_device *vdev)
{
	struct vfio_client_dev *vfio_client;
	struct device *dev = &vdev->dev;
	int ret;

	if (!virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		return -ENODEV;

	vfio_client = devm_kzalloc(dev, sizeof(*vfio_client), GFP_KERNEL);
	if (!vfio_client)
		return -ENOMEM;

	spin_lock_init(&vfio_client->request_lock);
	vfio_client->dev = dev;
	vfio_client->vdev = vdev;
	INIT_LIST_HEAD(&vfio_client->requests);

	ret = virtvfio_client_init_vqs(vfio_client);
	if (ret)
		return ret;

	virtio_device_ready(vdev);

	/* Populate the event queue with buffers */
	ret = virtvfio_client_fill_evtq(vfio_client);
	if (ret)
		goto err_free_vqs;

	vdev->priv = vfio_client;
	dev_err(dev, "probe OK\n");

	return 0;

err_free_vqs:
	vdev->config->del_vqs(vdev);

	return ret;
}

static void virtvfio_client_remove(struct virtio_device *vdev)
{
	struct vfio_client_dev *vfio_client = vdev->priv;

	/* Stop all virtqueues */
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	dev_err(&vdev->dev, "device removed\n");
}

static void virtvfio_client_config_changed(struct virtio_device *vdev)
{
	dev_err(&vdev->dev, "config changed\n");
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_VFIO, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
};

static struct virtio_driver virtio_vfio_client_drv = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.probe			= virtvfio_client_probe,
	.remove			= virtvfio_client_remove,
	.config_changed		= virtvfio_client_config_changed,
};

module_virtio_driver(virtio_vfio_client_drv);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Virtio VFIO client driver");
