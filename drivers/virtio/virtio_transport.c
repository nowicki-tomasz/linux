// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio transport driver for the para-virtualized VFIO platform device
 *
 * Copyright (C) 2020 Semihalf
 */

#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_transport.h>
#include <uapi/linux/virtio_vfio.h>

#define VIRTIO_TRANSPORT_REQUEST_VQ	0
#define VIRTIO_TRANSPORT_EVENT_VQ	1
#define VIRTIO_TRANSPORT_NR_VQS		2

struct virtio_trans {
	struct device			*dev;
	struct virtio_device		*vdev;

	struct virtqueue		*vqs[VIRTIO_TRANSPORT_NR_VQS];
	spinlock_t			request_lock;
	struct list_head		requests;
};

struct virtio_trans_req {
	struct list_head		list;
	void				*writeback;
	unsigned int			write_offset;
	unsigned int			len;
	char				buf[];
};

static int virtio_transport_get_req_errno(char *buf, size_t len)
{
	struct virtio_vfio_resp_status *resp =
		(struct virtio_vfio_resp_status *)(buf + len - sizeof(*resp));

	switch (resp->status) {
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
	case VIRTIO_VFIO_S_IOERR:
	case VIRTIO_VFIO_S_DEVERR:
	default:
		return -EIO;
	}
}

/*
 * __virtio_transport_sync_req - Complete all in-flight requests
 *
 * Wait for all added requests to complete. When this function returns, all
 * requests that were in-flight at the time of the call have completed.
 */
static int __virtio_transport_sync_req(struct virtio_trans *vtrans)
{
	struct virtqueue *vq = vtrans->vqs[VIRTIO_TRANSPORT_REQUEST_VQ];
	struct virtio_trans_req *req;
	unsigned int len;
	size_t write_len;
	int ret = 0;

	assert_spin_locked(&vtrans->request_lock);

	virtqueue_kick(vq);

	while (!list_empty(&vtrans->requests)) {
		len = 0;
		req = virtqueue_get_buf(vq, &len);
		if (!req)
			continue;

		write_len = req->len - req->write_offset;
		memcpy(req->writeback, req->buf + req->write_offset, write_len);

		list_del(&req->list);
		kfree(req);
	}

	return ret;
}

/*
 * __virtio_transport_add_req - Add one request to the queue
 * @vtrans: pointer to the transport layer
 * @buf: event buffer
 * @len: length of the event buffer
 *
 * Add a request to the queue. Data written by the device, including the req
 * status, is copied into @buf after the request completes.
 *
 * Return 0 if the request was successfully added to the queue.
 */
static int __virtio_transport_add_req(struct virtio_trans *vtrans, char *buf,
				      size_t len)
{
	struct virtqueue *vq = vtrans->vqs[VIRTIO_TRANSPORT_REQUEST_VQ];
	struct scatterlist top_sg, bottom_sg;
	struct scatterlist *sg[2] = { &top_sg, &bottom_sg };
	struct virtio_vfio_req_hdr *hdr;
	struct virtio_trans_req *req;
	off_t write_offset;
	int ret;

	assert_spin_locked(&vtrans->request_lock);

	req = kzalloc(sizeof(*req) + len, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	hdr = (struct virtio_vfio_req_hdr *)buf;
	write_offset = sizeof(*hdr) + hdr->req_len;

	req->len = len;
	req->writeback = buf + write_offset;
	req->write_offset = write_offset;
	memcpy(&req->buf, buf, write_offset);

	sg_init_one(&top_sg, req->buf, write_offset);
	sg_init_one(&bottom_sg, req->buf + write_offset, hdr->resp_len);

	ret = virtqueue_add_sgs(vq, sg, 1, 1, req, GFP_ATOMIC);
	if (ret == -ENOSPC) {
		/* If the queue is full, sync and retry */
		if (!__virtio_transport_sync_req(vtrans))
			ret = virtqueue_add_sgs(vq, sg, 1, 1, req, GFP_ATOMIC);
	}
	if (ret)
		goto err_free;

	list_add_tail(&req->list, &vtrans->requests);
	return 0;

err_free:
	kfree(req);
	return ret;
}

/*
 * Send a request and wait for it to complete. Return the request status (as an
 * errno)
 */
int virtio_transport_send_req_sync(struct virtio_trans *vtrans, void *buf,
				   size_t len)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&vtrans->request_lock, flags);
	ret = __virtio_transport_add_req(vtrans, buf, len);
	if (ret) {
		dev_err(vtrans->dev, "could not add request (%d)\n", ret);
		goto out_unlock;
	}

	ret = __virtio_transport_sync_req(vtrans);
	if (ret) {
		dev_err(vtrans->dev, "could not sync requests (%d)\n", ret);
		/* Fall-through (get the actual request status) */
	}

	ret = virtio_transport_get_req_errno(buf, len);
out_unlock:
	spin_unlock_irqrestore(&vtrans->request_lock, flags);
	return ret;
}

static int virtio_transport_init_vqs(struct virtio_trans *vtrans,
				     vq_callback_t *event)
{
	struct virtio_device *vdev = dev_to_virtio(vtrans->dev);
	const char *names[] = { "request", "event" };
	vq_callback_t *callbacks[] = {
		NULL, /* No async requests */
		event,
	};

	return virtio_find_vqs(vdev, VIRTIO_TRANSPORT_NR_VQS,
			       vtrans->vqs, callbacks, names, NULL);
}

/*
 * In order to have synchronous host to guest event notification
 * we ever expect to manage only one descriptor at a time which means that
 * guest prepares only one descriptor upfront and refill when consumed.
 */
static int virio_transport_fill_evtq(struct virtio_trans *vtrans,
				     size_t evt_size, size_t evt_status_size)
{
	struct virtqueue *vq = vtrans->vqs[VIRTIO_TRANSPORT_EVENT_VQ];
	struct scatterlist top_sg, bottom_sg;
	struct scatterlist *sg[2] = { &top_sg, &bottom_sg };
	uint8_t *buf;

	buf = devm_kzalloc(vtrans->dev, evt_size + evt_status_size,
			   GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	sg_init_one(&top_sg, buf, evt_status_size);
	sg_init_one(&bottom_sg, buf + evt_status_size, evt_size);
	return virtqueue_add_sgs(vq, sg, 1, 1, buf, GFP_ATOMIC);
}

struct virtio_trans *virtio_transport_init(struct virtio_device *vdev,
					   vq_callback_t *evt_cb,
					   size_t evt_sz, size_t evt_status_sz)
{
	struct device *dev = &vdev->dev;
	struct virtio_trans *vtrans;
	int ret;

	vtrans = devm_kzalloc(dev, sizeof(*vtrans), GFP_KERNEL);
	if (!vtrans)
		return ERR_PTR(-ENOMEM);

	vtrans->vdev = vdev;
	vtrans->dev = dev;
	spin_lock_init(&vtrans->request_lock);
	INIT_LIST_HEAD(&vtrans->requests);

	ret = virtio_transport_init_vqs(vtrans, evt_cb);
	if (ret)
		return ERR_PTR(ret);

	ret = virio_transport_fill_evtq(vtrans, evt_sz, evt_status_sz);
	if (ret) {
		vdev->config->del_vqs(vdev);
		return ERR_PTR(ret);
	}

	virtio_device_ready(vdev);
	return vtrans;
}

void virtio_transport_deinit(struct virtio_device *vdev)
{
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);
}
