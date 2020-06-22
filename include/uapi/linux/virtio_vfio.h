/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Virtio VFIO platform device definition
 *
 * Copyright (C) 2020 Semihalf Limited
 */
#ifndef _UAPI_LINUX_VIRTIO_VFIO_H
#define _UAPI_LINUX_VIRTIO_VFIO_H

#include <linux/types.h>

/* Status types */
#define VIRTIO_VFIO_S_OK		0x00
#define VIRTIO_VFIO_S_IOERR		0x01
#define VIRTIO_VFIO_S_UNSUPP		0x02
#define VIRTIO_VFIO_S_DEVERR		0x03
#define VIRTIO_VFIO_S_INVAL		0x04
#define VIRTIO_VFIO_S_RANGE		0x05
#define VIRTIO_VFIO_S_NOENT		0x06

#define VIRTIO_VFIO_MAX_BUF_SIZE	(1024 * 64)

struct virtio_vfio_req_hdr {
	__u8				dev_type;
	__u8				req_type;
	__u8				reserved[2];
	__le32				req_len;
	__le32				resp_len;
} __attribute__((packed));

struct virtio_vfio_req {
	struct virtio_vfio_req_hdr	hdr;
	__u8				buf[];
} __attribute__((packed));

struct virtio_vfio_resp_status {
	__u8				status;
	__u8				reserved[3];
} __attribute__((packed));

//int virtvfio_client_add_req(struct vfio_client_dev *vfio_client,
//			    void *buf, size_t len);
//int virtvfio_client_send_req_sync(struct vfio_client_dev *vfio_client,
//				  void *buf, size_t len);
//int virtvfio_client_sync_req(struct vfio_client_dev *vfio_client);

/* Clocks */
#define VIRTIO_VFIO_CLK_DEV_TYPE	0x01

/* Clock request types */
#define VIRTIO_VFIO_REQ_CLK_PREPARE		0x01
#define VIRTIO_VFIO_REQ_CLK_ENABLE		0x02
#define VIRTIO_VFIO_REQ_CLK_UNPREPARE		0x03
#define VIRTIO_VFIO_REQ_CLK_DISABLE		0x04
#define VIRTIO_VFIO_REQ_CLK_SET_RATE		0x05
#define VIRTIO_VFIO_REQ_CLK_GET_RATE		0x06
#define VIRTIO_VFIO_REQ_CLK_GET_FLAGS		0x07

#endif
