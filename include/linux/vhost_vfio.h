/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VHOST_VFIO_H
#define _LINUX_VHOST_VFIO_H

#include <linux/types.h>

struct vhost_dev;
extern int vhost_vfio_send_evt(struct vhost_dev *dev, void *buf, ssize_t size);

#endif /* _LINUX_VHOST_VFIO_H */
