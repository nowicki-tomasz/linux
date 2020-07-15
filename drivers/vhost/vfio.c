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

	struct vhost_work	evt_work;
	spinlock_t		evt_list_lock;
	struct list_head	evt_list;
	int			evt_head;
	struct iov_iter		evt_iov_iter;
	ssize_t			evt_size;
	uint32_t		evt_status;

	struct vfio_device	*vfio_dev_consumer;
	struct vhost_vfio_dev_info info;
};

struct vhost_vfio_evt {
	struct list_head	list;
	void			*buf;
	u32			size;
};

static void vhost_vfio_flush(struct vhost_vfio *vv)
{
	struct vhost_virtqueue *vq_req = &vv->vqs[VHOST_VFIO_VQ_REQUEST];

	vhost_work_flush(&vv->dev, &vv->evt_work);
	vhost_poll_flush(&vq_req->poll);
}

static void __vhost_vfio_stop(struct vhost_virtqueue *vq)
{
	mutex_lock(&vq->mutex);
	vq->private_data = NULL;
	mutex_unlock(&vq->mutex);
}

static long vhost_vfio_reset_owner(struct vhost_vfio *vv)
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

	__vhost_vfio_stop(&vv->vqs[VHOST_VFIO_VQ_REQUEST]);
	__vhost_vfio_stop(&vv->vqs[VHOST_VFIO_VQ_EVENT]);
	vhost_vfio_flush(vv);
	vhost_dev_reset_owner(&vv->dev, umem);
done:
	mutex_unlock(&vv->dev.mutex);
	return err;
}

static long vhost_vfio_set_owner(struct vhost_vfio *vv)
{
	int r;

	mutex_lock(&vv->dev.mutex);
	if (vhost_dev_has_owner(&vv->dev)) {
		r = -EBUSY;
		goto out;
	}

	r = vhost_dev_set_owner(&vv->dev);
	vhost_vfio_flush(vv);
out:
	mutex_unlock(&vv->dev.mutex);
	return r;
}

static int vhost_vfio_set_features(struct vhost_vfio *vv, u64 features)
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

static long vhost_vfio_set_fd(struct vhost_vfio *vv, void __user *argp)
{
	struct vhost_vfio_dev_info info;
	struct fd f;
	int fd, r = 0;

	if (copy_from_user(&info, argp, sizeof(info)))
		return -EFAULT;

	fd = info.vfio_consumer_fd;

	mutex_lock(&vv->dev.mutex);

	f = fdget(fd);
	if (!f.file) {
		r = -EBADF;
		goto out;
	}

	vv->vfio_dev_consumer = f.file->private_data;
	vv->info = info;
	fdput(f);

out:
	mutex_unlock(&vv->dev.mutex);
	return r;
}

static int __vhost_vfio_get_one_evt(struct vhost_vfio *vv)
{
	struct vhost_virtqueue *vq = &vv->vqs[VHOST_VFIO_VQ_EVENT];
	int ret = 0, count = 0;

	while (true) {
		struct iov_iter status_iov_iter;
		ssize_t status_sz, sz;
		unsigned out, in;
		int head;

		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
					 &out, &in, NULL, NULL);
		if (head < 0) {
			vq_err(vq, "Failed to obtain head, err %d\n", head);
			ret = head;
			break;
		}

		/*
		 * No available descriptor means that guest is processing
		 * the event
		 */
		if (head == vq->num) {
			if (count > 0)
				break;

			continue;
		}

		/* Out buffer will be used for subsequent host to guest event
		 * but in buffer contain current event status.
		 *  */
		vv->evt_head = head;
		vv->evt_size = iov_length(&vq->iov[out], in);
		iov_iter_init(&vv->evt_iov_iter, READ, &vq->iov[out], in,
			      vv->evt_size);

		status_sz = iov_length(vq->iov, out);
		iov_iter_init(&status_iov_iter, WRITE, vq->iov, out, status_sz);
		sz = copy_from_iter(&vv->evt_status, sizeof(vv->evt_status),
				    &status_iov_iter);
		if (sz != sizeof(vv->evt_status)) {
			vq_err(vq, "Expected %zu bytes for event status, got %zu bytes\n",
			       sizeof(vv->evt_status), sz);
		}

		count++;
	}

	/* More than one descriptor is illegal */
	ret = count != 1 ? -EINVAL : ret;
	if (ret)
		vv->evt_size = 0;

	return ret;
}

static int vhost_vfio_get_one_evt(struct vhost_vfio *vv)
{
	struct vhost_virtqueue *vq = &vv->vqs[VHOST_VFIO_VQ_EVENT];
	struct vhost_dev *dev = &vv->dev;
	int ret;

	mutex_lock(&vq->mutex);

	if (!vq->private_data) {
		mutex_unlock(&vq->mutex);
		return 0;
	}

	/* Avoid further vmexits, we're already processing the virtqueue */
	vhost_disable_notify(dev, vq);

	ret = __vhost_vfio_get_one_evt(vv);

	vhost_enable_notify(dev, vq);
	mutex_unlock(&vq->mutex);
	return ret;
}

/*
 * In order to have synchronous host to guest event notification
 * we ever expect to manage only one descriptor at a time which means that
 * guest prepares only one descriptor upfront and refill when receive an event.
 * 1. Guest push one desc which conveys in and out buf
 * 2. Host fills event info into the in buf and sends to guest
 * 3. Guest consumes event and refill queue with new desc
 * 4. At the same time guest updates prev operation status into the out buffer
 * 5. Host polls for available desc and read the status from out buf
 * 6. The same desc and its in buf  will be used for subsequent event
 *
 * Send an event and wait for it to complete. Return the event status.
 */
static int vhost_vfio_do_send_one_evt(struct vhost_vfio *vv,
				      struct vhost_virtqueue *vq)
{
	struct vhost_dev *dev = &vv->dev;
	struct vhost_vfio_evt *evt;
	size_t nbytes;
	int ret;

	mutex_lock(&vq->mutex);

	if (!vq->private_data) {
		mutex_unlock(&vq->mutex);
		return 0;
	}

	/* Avoid further vmexits, we're already processing the virtqueue */
	vhost_disable_notify(dev, vq);

	spin_lock(&vv->evt_list_lock);
	/* Expect only one event to send */
	if (WARN_ON(list_empty(&vv->evt_list) ||
		    !list_is_singular(&vv->evt_list))) {
		ret = -EINVAL;
		goto out;
	}

	evt = list_first_entry(&vv->evt_list,
			       struct vhost_vfio_evt, list);
	if (vv->evt_size < evt->size) {
		vq_err(vq, "Buffer len [%zu] too small\n", vv->evt_size);
		ret = -EINVAL;
		goto out;
	}

	nbytes = copy_to_iter(evt->buf, evt->size, &vv->evt_iov_iter);
	if (nbytes != evt->size) {
		vq_err(vq, "Faulted on copying event\n");
		ret = -EINVAL;
		goto out;
	}

	vhost_add_used_and_signal(dev, vq, vv->evt_head, evt->size);

	/* Wait until guest refill */
	ret = __vhost_vfio_get_one_evt(vv);
	if (ret)
		goto out;

	list_del_init(&evt->list);
out:
	spin_unlock(&vv->evt_list_lock);
	vhost_enable_notify(&vv->dev, vq);
	mutex_unlock(&vq->mutex);
	return ret;
}

static void vhost_vfio_event_work(struct vhost_work *work)
{
	struct vhost_virtqueue *vq;
	struct vhost_vfio *vv;

	vv = container_of(work, struct vhost_vfio, evt_work);
	vq = &vv->vqs[VHOST_VFIO_VQ_EVENT];

	vhost_vfio_do_send_one_evt(vv, vq);
}

int vhost_vfio_send_evt(struct vhost_dev *dev, void *buf, ssize_t size)
{
	struct vhost_vfio *vv = container_of(dev, struct vhost_vfio, dev);
	struct vhost_vfio_evt *evt;

	/* We can't send event to ourself, this leads to deadlock */
	if (!vhost_dev_check_owner(dev))
		return 0;

	evt = kzalloc(sizeof(*evt), GFP_KERNEL);
	if (!evt)
		return -ENOMEM;

	evt->buf = buf;
	evt->size = size;

	spin_lock(&vv->evt_list_lock);
	list_add_tail(&evt->list, &vv->evt_list);
	spin_unlock(&vv->evt_list_lock);

	vhost_work_queue(&vv->dev, &vv->evt_work);

	while (!list_empty(&vv->evt_list))
		cpu_relax();

	kfree(evt);
	return vv->evt_status;
}

static int vhost_vfio_start(struct vhost_vfio *vv)
{
	struct vhost_virtqueue *vq;
	struct vfio_vhost_info info;
	size_t i;
	int ret;

	mutex_lock(&vv->dev.mutex);

	ret = vhost_dev_check_owner(&vv->dev);
	if (ret)
		goto err;

	for (i = 0; i < ARRAY_SIZE(vv->vqs); i++) {
		vq = &vv->vqs[i];

		mutex_lock(&vq->mutex);

		if (!vhost_vq_access_ok(vq)) {
			ret = -EFAULT;
			goto err_vq;
		}

		if (!vq->private_data) {
			vq->private_data = vv;
			ret = vhost_vq_init_access(vq);
			if (ret)
				goto err_vq;
		}

		mutex_unlock(&vq->mutex);
	}

	ret = vhost_vfio_get_one_evt(vv);
	if (ret)
		goto err;

	info.vhost = &vv->dev;
	info.vhost_dev_index = vv->info.vhost_dev_index;
	info.vhost_dev_type = vv->info.vhost_dev_type;
	info.add = true;
	vfio_vhost_register(vv->vfio_dev_consumer, &info);
	mutex_unlock(&vv->dev.mutex);
	return 0;

err_vq:
	vq->private_data = NULL;
	mutex_unlock(&vq->mutex);

	for (i = 0; i < ARRAY_SIZE(vv->vqs); i++) {
		vq = &vv->vqs[i];

		mutex_lock(&vq->mutex);
		vq->private_data = NULL;
		mutex_unlock(&vq->mutex);
	}
err:
	mutex_unlock(&vv->dev.mutex);
	return ret;
}

static int vhost_vfio_stop(struct vhost_vfio *vv)
{
	struct vfio_vhost_info info;
	int ret, i;

	mutex_lock(&vv->dev.mutex);

	ret = vhost_dev_check_owner(&vv->dev);
	if (ret)
		goto err;

	info.vhost = &vv->dev;
	info.vhost_dev_index = vv->info.vhost_dev_index;
	info.vhost_dev_type = vv->info.vhost_dev_type;
	info.add = false;
	vfio_vhost_register(vv->vfio_dev_consumer, &info);

	for (i = 0; i < ARRAY_SIZE(vv->vqs); i++)
		__vhost_vfio_stop(&vv->vqs[i]);

err:
	mutex_unlock(&vv->dev.mutex);
	return ret;
}

static long vhost_vfio_ioctl(struct file *f, unsigned int ioctl,
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
		return vhost_vfio_set_features(vv, features);
	case VHOST_RESET_OWNER:
		return vhost_vfio_reset_owner(vv);
	case VHOST_SET_OWNER:
		return vhost_vfio_set_owner(vv);
	case VHOST_VFIO_SET_FD:
		return vhost_vfio_set_fd(vv, argp);
	case VHOST_VFIO_SET_RUNNING:
		if (copy_from_user(&start, argp, sizeof(start)))
			return -EFAULT;
		if (start)
			return vhost_vfio_start(vv);
		else
			return vhost_vfio_stop(vv);
	default:
		mutex_lock(&vv->dev.mutex);
		r = vhost_dev_ioctl(&vv->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&vv->dev, ioctl, argp);
		else
			vhost_vfio_flush(vv);
		mutex_unlock(&vv->dev.mutex);
		return r;
	}
}

static struct vfio_vhost_req *vhost_vfio_alloc_req(struct vhost_virtqueue *vq,
					     unsigned int out, unsigned int in)
{
	struct vhost_vfio *vv = container_of(vq->dev, struct vhost_vfio, dev);
	struct iov_iter out_iov_iter;
	size_t out_len, in_len, sz;
	size_t min_out, min_in;
	struct vfio_vhost_req *req;

	if (!in) {
		vq_err(vq, "Expected non-zero input buffers\n");
		return NULL;
	}

	out_len = iov_length(vq->iov, out);
	in_len = iov_length(&vq->iov[out], in);
	min_out = sizeof(struct virtio_vfio_req_hdr);
	min_in = sizeof(struct virtio_vfio_resp_status);
	if ((out_len < min_out || out_len > VFIO_VHOST_MAX_BUF_SIZE) ||
	    (in_len < min_in || in_len > VFIO_VHOST_MAX_BUF_SIZE)) {
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

	req->dev_idx = vv->info.vhost_dev_index;
	return req;
}

static void vhost_vfio_respond(struct vfio_vhost_req *req,
			       struct vhost_virtqueue *vq, unsigned int out,
			       unsigned int in)
{
	struct virtio_vfio_req *vq_req = (struct virtio_vfio_req *)req->vq_req;
	struct iov_iter in_iov_iter;
	size_t in_len, sz;

	in_len = iov_length(&vq->iov[out], in);
	iov_iter_init(&in_iov_iter, READ, &vq->iov[out], in, in_len);
	if (WARN_ON(unlikely(in_len < vq_req->hdr.resp_len)))
		vq_err(vq, "No enough space for response\n");

	sz = copy_to_iter(req->vq_resp, vq_req->hdr.resp_len, &in_iov_iter);
	if (WARN_ON(unlikely(sz != vq_req->hdr.resp_len)))
		vq_err(vq, "Faulted on copy in status\n");
	kfree(req);
}

static void vhost_vfio_handle_req(struct vhost_vfio *vv,
				   struct vhost_virtqueue *vq)
{
	unsigned int out = 0, in = 0;
	struct vfio_vhost_req *vfio_req;
	int head, c = 0, ret;

	mutex_lock(&vq->mutex);

	if (!vq->private_data)
		goto out;

	vhost_disable_notify(&vv->dev, vq);

	do {
		head = vhost_get_vq_desc(vq, vq->iov,
					 ARRAY_SIZE(vq->iov), &out, &in,
					 NULL, NULL);
		if (unlikely(head < 0))
			break;

		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&vv->dev, vq))) {
				vhost_disable_notify(&vv->dev, vq);
				continue;
			}
			break;
		}

		vfio_req = vhost_vfio_alloc_req(vq, out, in);
		if (!vfio_req) {
			vq_err(vq, "Faulted on request allocation\n");
			continue;
		}

		ret = vfio_vhost_req(vv->vfio_dev_consumer, vfio_req);
		if (ret) {
			vq_err(vq, "Request handling error %d\n", ret);
		}

		vhost_vfio_respond(vfio_req, vq, out, in);
		vhost_add_used_and_signal(&vv->dev, vq, head, 0);
	} while (likely(!vhost_exceeds_weight(vq, ++c, 0)));

out:
	mutex_unlock(&vq->mutex);
}

static void handle_rqst_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_vfio *vv = container_of(vq->dev, struct vhost_vfio, dev);

	vhost_vfio_handle_req(vv, vq);
}

static int vhost_vfio_open(struct inode *inode, struct file *f)
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
	vhost_work_init(&vv->evt_work, vhost_vfio_event_work);
	f->private_data = vv;

	return 0;
}

static int vhost_vfio_release(struct inode *inode, struct file *f)
{
	struct vhost_vfio *vv = f->private_data;

	__vhost_vfio_stop(&vv->vqs[VHOST_VFIO_VQ_REQUEST]);
	__vhost_vfio_stop(&vv->vqs[VHOST_VFIO_VQ_EVENT]);
	vhost_vfio_flush(vv);
	vhost_dev_stop(&vv->dev);
	vhost_dev_cleanup(&vv->dev);
	/* Make sure no callbacks are outstanding */
	synchronize_rcu();
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_vfio_flush(vv);
	kfree(vv->dev.vqs);
	kvfree(vv);
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
MODULE_DESCRIPTION("Host kernel interface for Virtio-based VFIO configuration");
MODULE_ALIAS_MISCDEV(VHOST_VFIO_MINOR);
MODULE_ALIAS("devname:vhost-vfio");
