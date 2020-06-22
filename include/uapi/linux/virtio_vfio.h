/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Virtio VFIO platform device definition
 *
 * Copyright (C) 2020 Semihalf
 */
#ifndef _UAPI_LINUX_VIRTIO_VFIO_H
#define _UAPI_LINUX_VIRTIO_VFIO_H

/* Status types */
#define VIRTIO_VFIO_S_OK		0x00
#define VIRTIO_VFIO_S_IOERR		0x01
#define VIRTIO_VFIO_S_UNSUPP		0x02
#define VIRTIO_VFIO_S_DEVERR		0x03
#define VIRTIO_VFIO_S_INVAL		0x04
#define VIRTIO_VFIO_S_RANGE		0x05
#define VIRTIO_VFIO_S_NOENT		0x06

#endif
