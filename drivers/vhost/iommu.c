/* Copyright (C) 2017 Semihalf sp. z o.o.
 * Author: Tomasz Nowicki <tn@semihalf.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * virtio-iommu in host kernel.
 */

#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/virtio_iommu.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/sched/clock.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>

static long vhost_iommu_ioctl(struct file *f, unsigned int ioctl,
			      unsigned long arg)
{
	struct vhost_net *n = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	struct vhost_vring_file backend;
	u64 features;
	int r;

	switch (ioctl) {
	case VHOST_GET_FEATURES:
		features = VIRTIO_RING_F_EVENT_IDX | VIRTIO_RING_F_INDIRECT_DESC |
			VIRTIO_IOMMU_F_INPUT_RANGE | VIRTIO_IOMMU_F_MAP_UNMAP |
			VIRTIO_IOMMU_F_PROBE;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		return 0;
	case VHOST_RESET_OWNER:
		return vhost_net_reset_owner(n);
	case VHOST_SET_OWNER:
		return vhost_net_set_owner(n);
	default:
		mutex_lock(&n->dev.mutex);
		r = vhost_dev_ioctl(&n->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&n->dev, ioctl, argp);
		else
			vhost_net_flush(n);
		mutex_unlock(&n->dev.mutex);
		return r;
	}
}

#ifdef CONFIG_COMPAT
static long vhost_net_compat_ioctl(struct file *f, unsigned int ioctl,
				   unsigned long arg)
{
	return vhost_iommu_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vhost_iommu_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_iommu_release,
	.unlocked_ioctl = vhost_iommu_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_iommu_compat_ioctl,
#endif
	.open           = vhost_iommu_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_iommu_misc = {
	.minor = VHOST_IOMMU_MINOR,
	.name = "vhost-iommu",
	.fops = &vhost_iommu_fops,
};

static int vhost_iommu_init(void)
{
	return misc_register(&vhost_iommu_misc);
}
module_init(vhost_iommu_init);

static void vhost_iommu_exit(void)
{
	misc_deregister(&vhost_iommu_misc);
}
module_exit(vhost_iommu_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki");
MODULE_DESCRIPTION("Host kernel accelerator for virtio iommu");
MODULE_ALIAS_MISCDEV(VHOST_IOMMU_MINOR);
MODULE_ALIAS("devname:vhost-iommu");
