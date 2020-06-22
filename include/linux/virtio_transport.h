/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_TRANSPORT_H
#define _LINUX_VIRTIO_TRANSPORT_H

#include <linux/types.h>
#include <linux/vringh.h>
#include <linux/virtio_config.h>

struct virtio_trans;
int virtio_transport_send_req_sync(struct virtio_trans *vtrans, void *buf,
				   size_t len);
struct virtio_trans *virtio_transport_init(struct virtio_device *vdev,
					   vq_callback_t *evt_cb,
					   size_t evt_sz, size_t evt_status_sz);
void virtio_transport_deinit(struct virtio_device *vdev);

#endif /* _LINUX_VIRTIO_TRANSPORT_H */
