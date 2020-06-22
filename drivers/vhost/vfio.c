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

#define VFIO_PLAT_MAX_REQ_LEN		0x1000
struct vhost_vfio {
	struct vhost_dev dev;
	struct vhost_work event_work;
	struct vhost_virtqueue vq_req;
	struct vhost_virtqueue vq_evt;
	struct vfio_device *vfio_consumer_dev;
	uint32_t vfio_consumer_fd;
	uint32_t vfio_compan_index;
	char buf[VFIO_PLAT_MAX_REQ_LEN];
};

static void vhost_vfio_flush(struct vhost_vfio *vi)
{
	vhost_work_flush(&vi->dev, &vi->event_work);
	vhost_poll_flush(&vi->vq_req.poll);
}

static void vhost_vfio_stop(struct vhost_vfio *vi, struct vhost_virtqueue *vq)
{
	mutex_lock(&vq->mutex);
	vq->private_data = NULL;
	mutex_unlock(&vq->mutex);
}

static long vhost_vfio_reset_owner(struct vhost_vfio *vi)
{
	long err;
	struct vhost_umem *umem;

	mutex_lock(&vi->dev.mutex);
	err = vhost_dev_check_owner(&vi->dev);
	if (err)
		goto done;

	umem = vhost_dev_reset_owner_prepare();
	if (!umem) {
		err = -ENOMEM;
		goto done;
	}

	vhost_vfio_stop(vi, &vi->vq_req);
	vhost_vfio_stop(vi, &vi->vq_evt);
	vhost_vfio_flush(vi);
	vhost_dev_reset_owner(&vi->dev, umem);
done:
	mutex_unlock(&vi->dev.mutex);
	return err;
}

static long vhost_vfio_set_owner(struct vhost_vfio *vi)
{
	int r;

	mutex_lock(&vi->dev.mutex);
	if (vhost_dev_has_owner(&vi->dev)) {
		r = -EBUSY;
		goto out;
	}

	r = vhost_dev_set_owner(&vi->dev);
	vhost_vfio_flush(vi);
out:
	mutex_unlock(&vi->dev.mutex);
	return r;
}

static int vhost_vfio_set_features(struct vhost_vfio *vi, u64 features)
{
	struct vhost_virtqueue *vq;

	mutex_lock(&vi->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&vi->dev)) {
		mutex_unlock(&vi->dev.mutex);
		return -EFAULT;
	}

	vq = &vi->vq_req;
	mutex_lock(&vq->mutex);
	vq->acked_features = features;
	mutex_unlock(&vq->mutex);

	vq = &vi->vq_evt;
	mutex_lock(&vq->mutex);
	vq->acked_features = features;
	mutex_unlock(&vq->mutex);

	mutex_unlock(&vi->dev.mutex);
	return 0;
}

static long vhost_vfio_set_fd(struct vhost_vfio *vi,
				   void __user *argp)
{
	struct vfio_companion_device info;
	struct fd f;
	int fd, index, r = 0;

	if (copy_from_user(&info, argp, sizeof(info)))
		return -EFAULT;

	fd = info.consumer_fd;
	index = info.companion_index;

	mutex_lock(&vi->dev.mutex);

	f = fdget(fd);
	if (!f.file) {
		r = -EBADF;
		goto out;
	}

	vi->vfio_consumer_dev = f.file->private_data;
	vi->vfio_consumer_fd = fd;
	vi->vfio_compan_index = index;
	fdput(f);

out:
	mutex_unlock(&vi->dev.mutex);
	return r;
}

static long vhost_vfio_ioctl(struct file *f, unsigned int ioctl,
			      unsigned long arg)
{
	struct vhost_vfio *vi = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int r;

	switch (ioctl) {
	case VHOST_GET_FEATURES:
		features = VHOST_VFIO_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, argp, sizeof(features)))
			return -EFAULT;
		return vhost_vfio_set_features(vi, features);
	case VHOST_RESET_OWNER:
		return vhost_vfio_reset_owner(vi);
	case VHOST_SET_OWNER:
		return vhost_vfio_set_owner(vi);
	case VHOST_VFIO_FD:
		return vhost_vfio_set_fd(vi, argp);
	default:
		mutex_lock(&vi->dev.mutex);
		r = vhost_dev_ioctl(&vi->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&vi->dev, ioctl, argp);
		else
			vhost_vfio_flush(vi);
		mutex_unlock(&vi->dev.mutex);
		return r;
	}
}

static struct vfio_req *vhost_vfio_alloc_req(struct vhost_virtqueue *vq,
					     unsigned int out, unsigned int in)
{
	struct vhost_vfio *vi = container_of(vq->dev, struct vhost_vfio, dev);
	struct iov_iter out_iov_iter;
	size_t out_len, in_len, sz;
	size_t min_out, min_in;
	struct vfio_req *req;

	if (!in) {
		vq_err(vq, "Expected non-zero input buffers\n");
		return NULL;
	}

	out_len = iov_length(vq->iov, out);
	in_len = iov_length(&vq->iov[out], in);

	min_out = sizeof(struct virtio_vfio_req_hdr);
	min_in = sizeof(struct virtio_vfio_resp_status);
	if ((out_len > VIRTIO_VFIO_MAX_BUF_SIZE || out_len < min_out) ||
	    (in_len > VIRTIO_VFIO_MAX_BUF_SIZE || in_len < min_in)) {
		return NULL;
	}

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	iov_iter_init(&out_iov_iter, WRITE, vq->iov, out, out_len);
	sz = copy_from_iter(&req->vq_req, out_len, &out_iov_iter);
	if (sz != out_len) {
		vq_err(vq, "Expected %zu bytes for request, got %zu bytes\n",
		       out_len, sz);
		kfree(req);
		return NULL;
	}

	req->vdev = vi->vfio_consumer_dev;
	req->index = vi->vfio_compan_index;
	return req;
}

static void vhost_vfio_respond(struct vfio_req *req,
			       struct vhost_virtqueue *vq, unsigned int out,
			       unsigned int in)
{
	struct virtio_vfio_req *vq_req = (struct virtio_vfio_req *)req->vq_req;
	struct iov_iter in_iov_iter;
	size_t in_len, sz;

	in_len = iov_length(&vq->iov[out], in);
	iov_iter_init(&in_iov_iter, READ, &vq->iov[out], in, in_len);

	sz = copy_to_iter(req->vq_resp, vq_req->hdr.resp_len, &in_iov_iter);
	if (WARN_ON(unlikely(sz != vq_req->hdr.resp_len)))
		vq_err(vq, "Faulted on copy in status\n");
	kfree(req);
}

static void vhost_vfio_handle_req(struct vhost_vfio *vi,
				   struct vhost_virtqueue *vq)
{
	unsigned int out = 0, in = 0;
	struct vfio_req *vfio_req;
	int head, c = 0, ret;
	size_t resp_sz;

	mutex_lock(&vq->mutex);
	vhost_disable_notify(&vi->dev, vq);

	do {
		head = vhost_get_vq_desc(vq, vq->iov,
					 ARRAY_SIZE(vq->iov), &out, &in,
					 NULL, NULL);
		if (unlikely(head < 0))
			break;

		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&vi->dev, vq))) {
				vhost_disable_notify(&vi->dev, vq);
				continue;
			}
			break;
		}

		vfio_req = vhost_vfio_alloc_req(vq, out, in);
		if (!vfio_req) {
			vq_err(vq, "Faulted on request allocation\n");
			continue;
		}

		ret = vfio_handle_req(vfio_req);
		if (ret) {
			vq_err(vq, "Request handling error %d\n", ret);
		}

		vhost_vfio_respond(vfio_req, vq, out, in);
		vhost_add_used_and_signal(&vi->dev, vq, head, 0);
	} while (likely(!vhost_exceeds_weight(vq, ++c, 0)));
	mutex_unlock(&vq->mutex);
}

static void handle_rqst_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_vfio *vi = container_of(vq->dev, struct vhost_vfio, dev);

	vhost_vfio_handle_req(vi, vq);
}

static void vhost_vfio_event_work(struct vhost_work *work)
{
	pr_err("vhost-vfio: page fault service not supported \n");
}

static int vhost_vfio_open(struct inode *inode, struct file *f)
{
	struct vhost_vfio *vi;
	struct vhost_dev *dev;
	struct vhost_virtqueue **vq;

	vi = kvmalloc(sizeof(*vi), GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!vi)
		return -ENOMEM;
	vq = kmalloc(sizeof(*vq), GFP_KERNEL);
	if (!vq) {
		kvfree(vi);
		return -ENOMEM;
	}

	dev = &vi->dev;
	vhost_work_init(&vi->event_work, vhost_vfio_event_work);
	vq[VHOST_VFIO_VQ_REQUEST] = &vi->vq_req;
	vq[VHOST_VFIO_VQ_EVENT] = &vi->vq_evt;
	vi->vq_req.handle_kick = handle_rqst_kick;
	vhost_dev_init(dev, vq, VHOST_VFIO_VQ_MAX, UIO_MAXIOV,
		       VHOST_VFIO_PKT_WEIGHT, 0);
	f->private_data = vi;

	return 0;
}

static int vhost_vfio_release(struct inode *inode, struct file *f)
{
	struct vhost_vfio *vi = f->private_data;

	vhost_vfio_stop(vi, &vi->vq_req);
	vhost_vfio_stop(vi, &vi->vq_evt);
	vhost_vfio_flush(vi);
	vhost_dev_stop(&vi->dev);
	vhost_dev_cleanup(&vi->dev);
	/* Make sure no callbacks are outstanding */
	synchronize_rcu();
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_vfio_flush(vi);
	kfree(vi->dev.vqs);
	kvfree(vi);
	return 0;
}

#ifdef CONFIG_COMPAT
static long vhost_vfio_compat_ioctl(struct file *f, unsigned int ioctl,
				     unsigned long arg)
{
	return vhost_vfio_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vhost_vfio_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_vfio_release,
	.unlocked_ioctl = vhost_vfio_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_vfio_compat_ioctl,
#endif
	.open           = vhost_vfio_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_vfio_misc = {
	.minor = VHOST_VFIO_MINOR,
	.name = "vhost-vfio",
	.fops = &vhost_vfio_fops,
};

static int vhost_vfio_init(void)
{
	return misc_register(&vhost_vfio_misc);
}
module_init(vhost_vfio_init);

static void vhost_vfio_exit(void)
{
	misc_deregister(&vhost_vfio_misc);
}
module_exit(vhost_vfio_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki <tn@semihalf.com>");
MODULE_DESCRIPTION("Host kernel interface for Virtio and VFIO devices");
MODULE_ALIAS_MISCDEV(VHOST_VFIO_MINOR);
MODULE_ALIAS("devname:vhost-vfio-platform");
