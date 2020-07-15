/* Copyright (C) 2017 Semihalf sp. z o.o.
 * Author: Tomasz Nowicki <tn@semihalf.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * virtio-vfio-plat accelerator in host kernel.
 */

#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/interval_tree_generic.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/sched/clock.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>
#include <linux/vhost.h>
#include <linux/vfio.h>
#include <linux/virtio_vfio.h>
#include <linux/workqueue.h>

#include "vhost.h"

enum {
    VHOST_VFIO_VQ_REQUEST = 0,
    VHOST_VFIO_VQ_EVENT = 1,
    VHOST_VFIO_VQ_MAX = 2,
};

enum {
	VHOST_VFIO_FEATURES = VHOST_FEATURES
};

#define VHOST_VFIO_PKT_WEIGHT 256

struct vhost_vfio {
	struct vhost_dev	dev;
	struct vhost_virtqueue	vqs[VHOST_VFIO_VQ_MAX];
};

static void vhost_pipe_flush(struct vhost_vfio *vv)
{
	struct vhost_virtqueue *vq_req = &vv->vqs[VHOST_VFIO_VQ_REQUEST];

	vhost_work_flush(&vv->dev, &vv->evt_work);
	vhost_poll_flush(&vq_req->poll);
}

static void __vhost_pipe_stop(struct vhost_virtqueue *vq)
{
	mutex_lock(&vq->mutex);
	vq->private_data = NULL;
	mutex_unlock(&vq->mutex);
}

static long vhost_pipe_reset_owner(struct vhost_vfio *vv)
{
	long err;
	struct vhost_umem *umem;

	mutex_lock(&vv->dev.mutex);
	err = vhost_dev_check_owner(&vv->dev);
	if (err)
		goto done;

	umem = vhost_dev_reset_owner_prepare();
	if (!umem) {
		err = -ENOMEM;
		goto done;
	}

	__vhost_pipe_stop(&vv->vqs[VHOST_VFIO_VQ_REQUEST]);
	__vhost_pipe_stop(&vv->vqs[VHOST_VFIO_VQ_EVENT]);
	vhost_pipe_flush(vv);
	vhost_dev_reset_owner(&vv->dev, umem);
done:
	mutex_unlock(&vv->dev.mutex);
	return err;
}

static long vhost_pipe_set_owner(struct vhost_vfio *vv)
{
	int r;

	mutex_lock(&vv->dev.mutex);
	if (vhost_dev_has_owner(&vv->dev)) {
		r = -EBUSY;
		goto out;
	}

	r = vhost_dev_set_owner(&vv->dev);
	vhost_pipe_flush(vv);
out:
	mutex_unlock(&vv->dev.mutex);
	return r;
}

static int vhost_pipe_set_features(struct vhost_vfio *vv, u64 features)
{
	struct vhost_virtqueue *vq;
	int i;

	if (features & ~VHOST_VFIO_FEATURES)
		return -EOPNOTSUPP;

	mutex_lock(&vv->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&vv->dev)) {
		mutex_unlock(&vv->dev.mutex);
		return -EFAULT;
	}

	for (i = 0; i < ARRAY_SIZE(vv->vqs); i++) {
		vq = &vv->vqs[i];
		mutex_lock(&vq->mutex);
		vq->acked_features = features;
		mutex_unlock(&vq->mutex);
	}
	mutex_unlock(&vv->dev.mutex);
	return 0;
}

static void vhost_vfio_event_work(struct vhost_work *work)
{
}

static long vhost_pipe_ioctl(struct file *f, unsigned int ioctl,
			      unsigned long arg)
{
	struct vhost_vfio *vv = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int r, start;

	switch (ioctl) {
	case VHOST_GET_FEATURES:
		features = VHOST_VFIO_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, argp, sizeof(features)))
			return -EFAULT;
		return vhost_pipe_set_features(vv, features);
	case VHOST_RESET_OWNER:
		return vhost_pipe_reset_owner(vv);
	case VHOST_SET_OWNER:
		return vhost_pipe_set_owner(vv);
	default:
		mutex_lock(&vv->dev.mutex);
		r = vhost_dev_ioctl(&vv->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&vv->dev, ioctl, argp);
		else
			vhost_pipe_flush(vv);
		mutex_unlock(&vv->dev.mutex);
		return r;
	}
}

static void handle_rqst_kick(struct vhost_work *work)
{
}

static int vhost_pipe_open(struct inode *inode, struct file *f)
{
	struct vhost_virtqueue **vqs;
	struct vhost_vfio *vv;

	vv = kvzalloc(sizeof(*vv), GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!vv)
		return -ENOMEM;

	vqs = kmalloc_array(ARRAY_SIZE(vv->vqs), sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		kvfree(vv);
		return -ENOMEM;
	}

	vqs[VHOST_VFIO_VQ_REQUEST] = &vv->vqs[VHOST_VFIO_VQ_REQUEST];
	vqs[VHOST_VFIO_VQ_EVENT] = &vv->vqs[VHOST_VFIO_VQ_EVENT];
	vv->vqs[VHOST_VFIO_VQ_REQUEST].handle_kick = handle_rqst_kick;
	vhost_dev_init(&vv->dev, vqs, ARRAY_SIZE(vv->vqs), UIO_MAXIOV,
		       VHOST_VFIO_PKT_WEIGHT, 0);

	spin_lock_init(&vv->evt_list_lock);
	INIT_LIST_HEAD(&vv->evt_list);
	vhost_work_init(&vv->evt_work, vhost_pipe_event_work);
	f->private_data = vv;

	return 0;
}

static int vhost_pipe_release(struct inode *inode, struct file *f)
{
	struct vhost_vfio *vv = f->private_data;

	__vhost_pipe_stop(&vv->vqs[VHOST_VFIO_VQ_REQUEST]);
	__vhost_pipe_stop(&vv->vqs[VHOST_VFIO_VQ_EVENT]);
	vhost_pipe_flush(vv);
	vhost_dev_stop(&vv->dev);
	vhost_dev_cleanup(&vv->dev);
	/* Make sure no callbacks are outstanding */
	synchronize_rcu();
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_pipe_flush(vv);
	kfree(vv->dev.vqs);
	kvfree(vv);
	return 0;
}

#ifdef CONFIG_COMPAT
static long vhost_pipe_compat_ioctl(struct file *f, unsigned int ioctl,
				     unsigned long arg)
{
	return vhost_pipe_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vhost_pipe_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_pipe_release,
	.unlocked_ioctl = vhost_pipe_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_pipe_compat_ioctl,
#endif
	.open           = vhost_pipe_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_pipe_misc = {
	.minor = VHOST_VFIO_MINOR,
	.name = "vhost-pipe",
	.fops = &vhost_pipe_fops,
};

static int vhost_pipe_init(void)
{
	return misc_register(&vhost_pipe_misc);
}
module_init(vhost_pipe_init);

static void vhost_pipe_exit(void)
{
	misc_deregister(&vhost_pipe_misc);
}
module_exit(vhost_pipe_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Host kernel medium for Virtio-based configuration requests handling");
MODULE_ALIAS_MISCDEV(VHOST_VFIO_MINOR);
MODULE_ALIAS("devname:vhost-pipe");
