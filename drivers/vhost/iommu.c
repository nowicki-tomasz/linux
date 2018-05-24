/* Copyright (C) 2017 Semihalf sp. z o.o.
 * Author: Tomasz Nowicki <tn@semihalf.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * virtio-iommu accelerator in host kernel.
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
#include <linux/virtio_iommu.h>
#include <linux/workqueue.h>

#include "vhost.h"

enum {
    VHOST_IOMMU_VQ_REQUEST = 0,
    VHOST_IOMMU_VQ_EVENT = 1,
    VHOST_IOMMU_VQ_MAX = 2,
};

enum {
	VHOST_IOMMU_FEATURES = VHOST_FEATURES |
				(1ULL << VIRTIO_IOMMU_F_INPUT_RANGE) |
				(1ULL << VIRTIO_IOMMU_F_MAP_UNMAP)
				/* (1ULL << VIRTIO_IOMMU_F_PROBE) */
};

struct viommu_dev {
	struct list_head	list_iommu;
	struct list_head	list_as;
	struct vhost_dev	*dev;
	uint32_t		dev_fd;
	uint32_t		devid;
};

struct viommu_interval {
	uint64_t		low;
	uint64_t		high;
};

struct vhost_iommu_node {
	struct list_head	list;
	struct vhost_iommu	*vi;
	uint32_t		iommu_fd;
};

struct vhost_iommu {
	struct vhost_dev dev;
	struct list_head avail_devices;
	struct list_head attached_devices;
	struct vhost_work event_work;
	struct rb_root rbroot_as;
	spinlock_t as_rbtree_lock; /* Lock to protect update of rbtree */
	spinlock_t lock;
	uint32_t iommu_fd;
	struct vhost_virtqueue vq_req;
	struct vhost_virtqueue vq_evt;
	struct virtio_iommu_config config;
};

struct vhost_iommu_as {
	struct vhost_iommu *vi;
	struct rb_root_cached rbroot_mapping;
	spinlock_t mapping_rbtree_lock; /* Lock to protect update of rbtree */
	struct rb_node node;
	struct list_head devices;
	uint32_t asid;
	struct kref kref;
};

static LIST_HEAD(vhost_iommu_list);
static DEFINE_SPINLOCK(vhost_iommu_lock);

#define VIOMMU_START(node) ((node)->start)
#define VIOMMU_LAST(node) ((node)->last)
INTERVAL_TREE_DEFINE(struct vhost_umem_node,
		     rb_iommu, __u64, __subtree_last_iommu,
		     VIOMMU_START, VIOMMU_LAST,
		     static inline, vhost_iommu_interval_tree);

static int vhost_iommu_register(struct vhost_iommu *vi, uint32_t iommu_fd)
{
	struct vhost_iommu_node *vi_node;

	vi_node = kzalloc(sizeof(*vi_node), GFP_KERNEL);
	if (!vi_node)
		return -ENOMEM;

	vi_node->vi = vi;
	vi_node->iommu_fd = iommu_fd;

	spin_lock(&vhost_iommu_lock);
	list_add(&vi_node->list, &vhost_iommu_list);
	spin_unlock(&vhost_iommu_lock);

	return 0;
}

static void vhost_iommu_deregister(uint32_t iommu_fd)
{
	struct vhost_iommu_node *vi_node, *t;

	spin_lock(&vhost_iommu_lock);
	list_for_each_entry_safe(vi_node, t, &vhost_iommu_list, list) {
		if (vi_node->iommu_fd == iommu_fd) {
			list_del(&vi_node->list);
			kfree(vi_node);
			break;
		}
	}
	spin_unlock(&vhost_iommu_lock);
}

static struct vhost_iommu *vhost_iommu_find(uint32_t iommu_fd)
{
	struct vhost_iommu *vi = NULL;
	struct vhost_iommu_node *vi_node;

	spin_lock(&vhost_iommu_lock);
	list_for_each_entry(vi_node, &vhost_iommu_list, list) {
		if (vi_node->iommu_fd == iommu_fd) {
			vi = vi_node->vi;
			break;
		}
	}
	spin_unlock(&vhost_iommu_lock);
	return vi;
}

int vhost_iommu_attach_dev(struct vhost_dev *dev, struct vhost_iommu_bind *bind)
{
	struct vhost_iommu *vi;
	struct viommu_dev *vd;

	vi = vhost_iommu_find(bind->iommu_fd);
	if (!vi)
		return -ENODEV;

	vd = kzalloc(sizeof(struct vhost_iommu), GFP_KERNEL);
	if (vd == NULL)
		return -ENOMEM;

	vd->dev = dev;
	vd->dev_fd = bind->dev_fd;
	vd->devid = bind->devid;

	spin_lock(&vi->lock);
	list_add(&vd->list_iommu, &vi->avail_devices);
	spin_unlock(&vi->lock);

	return 0;
}

static void vhost_iommu_flush(struct vhost_iommu *vi)
{
	vhost_work_flush(&vi->dev, &vi->event_work);
	vhost_poll_flush(&vi->vq_req.poll);
}

static void vhost_iommu_stop(struct vhost_iommu *vi, struct vhost_virtqueue *vq)
{
	mutex_lock(&vq->mutex);
	vq->private_data = NULL;
	mutex_unlock(&vq->mutex);
}

static long vhost_iommu_reset_owner(struct vhost_iommu *vi)
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

	vhost_iommu_stop(vi, &vi->vq_req);
	vhost_iommu_stop(vi, &vi->vq_evt);
	vhost_iommu_flush(vi);
	vhost_dev_reset_owner(&vi->dev, umem);
done:
	mutex_unlock(&vi->dev.mutex);
	return err;
}

static long vhost_iommu_set_owner(struct vhost_iommu *vi)
{
	int r;

	mutex_lock(&vi->dev.mutex);
	if (vhost_dev_has_owner(&vi->dev)) {
		r = -EBUSY;
		goto out;
	}

	r = vhost_dev_set_owner(&vi->dev);
	vhost_iommu_flush(vi);
out:
	mutex_unlock(&vi->dev.mutex);
	return r;
}

static int vhost_iommu_set_features(struct vhost_iommu *vi, u64 features)
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

static struct viommu_dev *vhost_iommu_get_dev(struct vhost_iommu *vi,
						   uint32_t devid)
{
	struct viommu_dev *dev;
	int found = 0;

	/* Check if vhost device is really behind the IOMMU */
	spin_lock(&vi->lock);
	list_for_each_entry(dev, &vi->attached_devices, list_iommu) {
		if (dev->devid == devid) {
			found = 1;
			break;
		}
	}
	spin_unlock(&vi->lock);
	return found ? dev : NULL;
}

static int vhost_iommu_xlate(struct vhost_iommu *vi,
			     struct vhost_iommu_xlate *xlate, u64 *xlate_addr)
{
	u64 addr = xlate->imsg.iova;
	u32 access = xlate->imsg.perm;
	struct vhost_umem_node *node;
	struct viommu_dev *dev;

	dev = vhost_iommu_get_dev(vi, xlate->devid);
	if (!dev)
		return -EFAULT;

	node = vhost_iommu_translate(dev->dev->iommu_as, addr, addr + 1, access);
	if (node == NULL)
		return -EFAULT;

	*xlate_addr = node->phys_addr + addr - node->start;
	return 0;
}

static long vhost_iommu_ioctl(struct file *f, unsigned int ioctl,
			      unsigned long arg)
{
	struct vhost_iommu *vi = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	struct vhost_iommu_xlate xlate;
	u64 features;
	u64 uaddr;
	int r;

	switch (ioctl) {
	case VHOST_GET_FEATURES:
		features = VHOST_IOMMU_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, argp, sizeof(features)))
			return -EFAULT;
		return vhost_iommu_set_features(vi, features);
	case VHOST_RESET_OWNER:
		return vhost_iommu_reset_owner(vi);
	case VHOST_SET_OWNER:
		return vhost_iommu_set_owner(vi);
	case VHOST_IOMMU_ID:
		if (copy_from_user(&vi->iommu_fd, argp, sizeof(vi->iommu_fd)))
			return -EFAULT;

		vhost_iommu_register(vi, vi->iommu_fd);
		return 0;
	case VHOST_IOMMU_CONFIG:
		if (copy_from_user(&vi->config, argp, sizeof(vi->config)))
			return -EFAULT;

		return 0;
	case VHOST_IOMMU_XLATE:
		if (copy_from_user(&xlate, argp, sizeof(xlate)))
			return -EFAULT;

		if (vhost_iommu_xlate(vi, &xlate, &uaddr))
			return -EFAULT;

		xlate.imsg.uaddr = uaddr;
		if (copy_to_user(argp, &xlate, sizeof(xlate)))
			return -EFAULT;

		return 0;
	default:
		mutex_lock(&vi->dev.mutex);
		r = vhost_dev_ioctl(&vi->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&vi->dev, ioctl, argp);
		else
			vhost_iommu_flush(vi);
		mutex_unlock(&vi->dev.mutex);
		return r;
	}
}

static struct viommu_dev *vhost_iommu_add_dev(struct vhost_iommu *vi,
					      struct viommu_dev *dev)
{
	struct viommu_dev *iter;

	/* Check if vhost device is already attached */
	spin_lock(&vi->lock);
	list_for_each_entry(iter, &vi->attached_devices, list_iommu) {
		if (iter->devid == dev->devid) {
			spin_unlock(&vi->lock);
			return iter;
		}
	}

	/* Move device to attached devices list */
	list_del(&dev->list_iommu);
	/* New device */
	list_add(&dev->list_iommu, &vi->attached_devices);
	spin_unlock(&vi->lock);
	return dev;
}

static struct vhost_iommu_as *as_rb_search(struct vhost_iommu *vi, uint32_t asid)
{
	struct rb_node *node = vi->rbroot_as.rb_node;  /* top of the tree */

	assert_spin_locked(&vi->as_rbtree_lock);

	while (node) {
		struct vhost_iommu_as *this = rb_entry(node, struct vhost_iommu_as, node);

		if (this->asid > asid)
			node = node->rb_left;
		else if (this->asid < asid)
			node = node->rb_right;
		else {
			kref_get(&this->kref);
			return this;  /* Found it */
		}
	}
	return NULL;
}

static void as_rb_insert(struct vhost_iommu *vi, struct vhost_iommu_as *new_as)
{
	struct rb_node **link = &vi->rbroot_as.rb_node, *parent = NULL;
	uint32_t asid = new_as->asid;
	struct vhost_iommu_as *this;

	assert_spin_locked(&vi->as_rbtree_lock);

	/* Go to the bottom of the tree */
	while (*link)
	{
		parent = *link;
		this = rb_entry(parent, struct vhost_iommu_as, node);

		if (this->asid > asid)
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}

	/* Put the new node there */
	rb_link_node(&new_as->node, parent, link);
	rb_insert_color(&new_as->node, &vi->rbroot_as);
}

static struct vhost_iommu_as *vhost_iommu_get_as(struct vhost_iommu *vi,
					    uint32_t asid)
{
	struct vhost_iommu_as *as;

	spin_lock(&vi->as_rbtree_lock);
	as = as_rb_search(vi, asid);
	if (as) {
		spin_unlock(&vi->as_rbtree_lock);
		return as;
	}

	as = kmalloc(sizeof(*as), GFP_KERNEL);
	if (!as)
		return NULL;

	/* New AS */
	as->asid = asid;
	as->rbroot_mapping = RB_ROOT_CACHED;
	as->vi = vi;
	spin_lock_init(&as->mapping_rbtree_lock);
	INIT_LIST_HEAD(&as->devices);
	kref_init(&as->kref);
	as_rb_insert(vi, as);
	spin_unlock(&vi->as_rbtree_lock);
	return as;
}

static void vhost_iommu_remove_as(struct kref *kref)
{
	struct vhost_iommu_as *as = container_of(kref, struct vhost_iommu_as, kref);
	struct vhost_iommu *vi = as->vi;

	spin_lock(&vi->as_rbtree_lock);
	rb_erase(&as->node, &vi->rbroot_as);
	spin_unlock(&vi->as_rbtree_lock);

	kfree(as);
}

static int vhost_iommu_remove_dev(struct vhost_iommu *vi,
				  uint32_t devid)
{
	struct viommu_dev *dev, *tmp;
	int found = 0;

	spin_lock(&vhost_iommu_lock);
	list_for_each_entry_safe(dev, tmp, &vi->attached_devices, list_iommu) {
		if (dev->devid == devid) {
			list_del(&dev->list_as);
			/* Put device back to pool */
			list_del(&dev->list_iommu);
			list_add(&dev->list_iommu, &vi->avail_devices);
			found = 1;
			break;
		}
	}
	spin_unlock(&vhost_iommu_lock);

	if (found)
		kref_put(&dev->dev->iommu_as->kref, vhost_iommu_remove_as);
	return found ? 0 : -1;
}

static struct viommu_dev *vhost_iommu_validate_dev(struct vhost_iommu *vi,
						   uint32_t devid)
{
	struct viommu_dev *dev;
	int found = 0;

	/* Check if vhost device is really behind the IOMMU */
	spin_lock(&vi->lock);
	list_for_each_entry(dev, &vi->avail_devices, list_iommu) {
		if (dev->devid == devid) {
			found = 1;
			break;
		}
	}
	spin_unlock(&vi->lock);
	return found ? dev : NULL;
}

#define get_payload_size(req) (\
sizeof((req)) - sizeof(struct virtio_iommu_req_tail) - sizeof(struct virtio_iommu_req_head))

static int vhost_iommu_attach(struct vhost_iommu *vi,
			      struct vhost_virtqueue *vq,
			      struct virtio_iommu_req_attach *req)
{
	uint32_t asid, devid, reserved;
	struct viommu_dev *dev;
	struct vhost_iommu_as *as;

	asid = vhost32_to_cpu(vq, req->domain);
	devid = vhost32_to_cpu(vq, req->endpoint);
	reserved = vhost32_to_cpu(vq, req->reserved);
	if (reserved)
		return VIRTIO_IOMMU_S_INVAL;

	dev = vhost_iommu_validate_dev(vi, devid);
	if (!dev)
		return VIRTIO_IOMMU_S_NOENT;

	dev = vhost_iommu_add_dev(vi, dev);
	if (!dev)
		return VIRTIO_IOMMU_S_NOENT;

	as = vhost_iommu_get_as(vi, asid);
	if (!as)
		return VIRTIO_IOMMU_S_NOENT;

	dev->dev->iommu_as = as;

	spin_lock(&vi->lock);
	list_add(&dev->list_as, &as->devices);
	spin_unlock(&vi->lock);

	return VIRTIO_IOMMU_S_OK;
}

static int vhost_iommu_detach(struct vhost_iommu *vi,
			      struct vhost_virtqueue *vq,
			      struct virtio_iommu_req_detach *req)
{
	uint32_t devid, reserved;

	devid = vhost32_to_cpu(vq, req->endpoint);
	reserved = vhost32_to_cpu(vq, req->reserved);
	if (reserved)
		return VIRTIO_IOMMU_S_INVAL;

	if (vhost_iommu_remove_dev(vi, devid))
		return VIRTIO_IOMMU_S_NOENT;

	return VIRTIO_IOMMU_S_OK;
}

static int vhost_iommu_map(struct vhost_iommu *vi,
			   struct vhost_virtqueue *vq,
			   struct virtio_iommu_req_map *req)
{
	uint64_t phys_start, virt_start, virt_end, size;
	struct vhost_umem_node *node;
	uint32_t asid, flags, perm;
	struct vhost_iommu_as *as;

	asid = vhost32_to_cpu(vq, req->domain);
	phys_start = vhost64_to_cpu(vq, req->phys_start);
	virt_start = vhost64_to_cpu(vq, req->virt_start);
	virt_end = vhost64_to_cpu(vq, req->virt_end);
	size = virt_end - virt_start + 1;
	flags = vhost32_to_cpu(vq, req->flags);

	spin_lock(&vi->as_rbtree_lock);
	as = as_rb_search(vi, asid);
	if (!as) {
		spin_unlock(&vi->as_rbtree_lock);
		return VIRTIO_IOMMU_S_NOENT;
	}
	spin_unlock(&vi->as_rbtree_lock);

	switch (flags) {
	case VIRTIO_IOMMU_MAP_F_READ:
		perm = VHOST_ACCESS_RO;
		break;
	case VIRTIO_IOMMU_MAP_F_WRITE:
		perm = VHOST_ACCESS_WO;
		break;
	case VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE:
		perm = VHOST_ACCESS_RW;
		break;
	default:
	    return VIRTIO_IOMMU_S_INVAL;
	}

	node = kmalloc(sizeof(*node), GFP_ATOMIC);
	node->start = virt_start;
	node->last = virt_end;
	node->phys_addr = phys_start;
	node->size = size;
	node->perm = perm;
	node->userspace_addr = 0;
	node->iommu_owner = 1;

	spin_lock(&as->mapping_rbtree_lock);

	if (vhost_iommu_interval_tree_iter_first(&as->rbroot_mapping,
			virt_start, virt_end)) {
		spin_unlock(&as->mapping_rbtree_lock);
		return VIRTIO_IOMMU_S_INVAL;
	}

	vhost_iommu_interval_tree_insert(node, &as->rbroot_mapping);
	spin_unlock(&as->mapping_rbtree_lock);

	return VIRTIO_IOMMU_S_OK;
}

static int vhost_iommu_unmap(struct vhost_iommu *vi,
			     struct vhost_virtqueue *vq,
			     struct virtio_iommu_req_unmap *req)
{
	struct vhost_umem_node *node;
	uint64_t virt_start, virt_end, size;
	struct vhost_iommu_as *as;
	uint32_t asid;

	asid = vhost32_to_cpu(vq, req->domain);
	virt_start = vhost64_to_cpu(vq, req->virt_start);
	virt_end = vhost64_to_cpu(vq, req->virt_end);
	size = virt_end - virt_start + 1;

	spin_lock(&vi->as_rbtree_lock);
	as = as_rb_search(vi, asid);
	if (!as) {
		spin_unlock(&vi->as_rbtree_lock);
		return VIRTIO_IOMMU_S_NOENT;
	}
	spin_unlock(&vi->as_rbtree_lock);

	spin_lock(&as->mapping_rbtree_lock);
	node = vhost_iommu_interval_tree_iter_first(&as->rbroot_mapping,
			virt_start, virt_end);
	if (node == NULL) {
		spin_unlock(&as->mapping_rbtree_lock);
		return VIRTIO_IOMMU_S_OK;
	}


	while (node) {
		struct viommu_dev *dev;

		if (node->start == virt_start && size >= node->size) {
			vhost_iommu_interval_tree_remove(node, &as->rbroot_mapping);
			spin_unlock(&as->mapping_rbtree_lock);

			list_for_each_entry(dev, &as->devices, list_as)
				vhost_iommu_iotlb_inv(dev->dev, node);

			virt_start = node->last + 1;

		 } else if (node->last == virt_end && size >= node->size) {
			 vhost_iommu_interval_tree_remove(node, &as->rbroot_mapping);
			spin_unlock(&as->mapping_rbtree_lock);

			list_for_each_entry(dev, &as->devices, list_as)
				vhost_iommu_iotlb_inv(dev->dev, node);

			virt_end = node->start - 1;

		} else if (node->start > virt_start && node->last < virt_end) {
			vhost_iommu_interval_tree_remove(node, &as->rbroot_mapping);
			spin_unlock(&as->mapping_rbtree_lock);

			list_for_each_entry(dev, &as->devices, list_as)
				vhost_iommu_iotlb_inv(dev->dev, node);

		} else {
			spin_unlock(&as->mapping_rbtree_lock);
			kfree(node);
			return VIRTIO_IOMMU_S_INVAL;
		}

		kfree(node);
		if (virt_start >= virt_end) {
			break;
		} else {
			spin_lock(&as->mapping_rbtree_lock);
			node = vhost_iommu_interval_tree_iter_first(&as->rbroot_mapping,
					virt_start, virt_end);
			if (node == NULL)
				spin_unlock(&as->mapping_rbtree_lock);
		}
	}

	return VIRTIO_IOMMU_S_OK;
}

struct vhost_umem_node *vhost_iommu_translate(struct vhost_iommu_as *as,
					     u64 addr, u64 end, int access)
{
	struct vhost_umem_node *node;

	spin_lock(&as->mapping_rbtree_lock);
	node = vhost_iommu_interval_tree_iter_first(&as->rbroot_mapping,
				addr, end);
	if (!node || !(node->perm & access))
		node = NULL;
	spin_unlock(&as->mapping_rbtree_lock);

	/* Enqueue page fault if necessary */
	if (node == NULL)
		vhost_work_queue(&as->vi->dev, &as->vi->event_work);

	return node;
}

static void vhost_iommu_handle_req(struct vhost_iommu *vi,
				   struct vhost_virtqueue *vq)
{
	size_t req_size = sizeof(struct virtio_iommu_req_head);
	size_t resp_size = sizeof(struct virtio_iommu_req_tail);
	struct virtio_iommu_req_tail resp_tail;
	struct iov_iter out_iter, in_iter;
	union virtio_iommu_req req;
	size_t out_size, in_size;
	unsigned int out = 0, in = 0;
	int head;

	mutex_lock(&vq->mutex);
	vhost_disable_notify(&vi->dev, vq);

	for (;;) {
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

		out_size = iov_length(vq->iov, out);
		in_size = iov_length(&vq->iov[out], in);
		if (unlikely(out_size < req_size) ||
		    unlikely(in_size < resp_size)) {
			pr_err("vhost-iommu erroneous head or tail\n");
			break;
		}

		iov_iter_init(&out_iter, WRITE, vq->iov, out, out_size);
		if (unlikely(!copy_from_iter_full(&req, out_size, &out_iter))) {
			pr_err("vhost-iommu: Faulted on copy_from_iter_full\n");
			break;
		}

		switch (req.head.type) {
		case VIRTIO_IOMMU_T_ATTACH:
			resp_tail.status = vhost_iommu_attach(vi, vq, &req.attach);
			break;
		case VIRTIO_IOMMU_T_DETACH:
			resp_tail.status = vhost_iommu_detach(vi, vq, &req.detach);
			break;
		case VIRTIO_IOMMU_T_MAP:
			resp_tail.status = vhost_iommu_map(vi, vq, &req.map);
			break;
		case VIRTIO_IOMMU_T_UNMAP:
			resp_tail.status = vhost_iommu_unmap(vi, vq, &req.unmap);
			break;
		/* case VIRTIO_IOMMU_T_PROBE:
			break; */
		default:
			pr_err("vhost-iommu: unsupported command\n");
			resp_tail.status = VIRTIO_IOMMU_S_UNSUPP;
		}

		iov_iter_init(&in_iter, READ, &vq->iov[out], in, in_size);
		if (unlikely(!copy_from_iter_full(&resp_tail, resp_size,
				&in_iter))) {
			pr_err("vhost-iommu: Faulted on copy_from_iter_full\n");
			break;
		}

		vhost_add_used_and_signal(&vi->dev, vq, head, resp_size);
	}
	mutex_unlock(&vq->mutex);
}

static void handle_rqst_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_iommu *vi = container_of(vq->dev, struct vhost_iommu, dev);

	vhost_iommu_handle_req(vi, vq);
}

static void vhost_iommu_event_work(struct vhost_work *work)
{
	pr_err("vhost-iommu: page fault service not supported \n");
}

static int vhost_iommu_open(struct inode *inode, struct file *f)
{
	struct vhost_iommu *vi;
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
	INIT_LIST_HEAD(&vi->avail_devices);
	INIT_LIST_HEAD(&vi->attached_devices);
	vhost_work_init(&vi->event_work, vhost_iommu_event_work);
	vi->rbroot_as = RB_ROOT;
	spin_lock_init(&vi->as_rbtree_lock);
	spin_lock_init(&vi->lock);
	vq[VHOST_IOMMU_VQ_REQUEST] = &vi->vq_req;
	vq[VHOST_IOMMU_VQ_EVENT] = &vi->vq_evt;
	vi->vq_req.handle_kick = handle_rqst_kick;
	vhost_dev_init(dev, vq, VHOST_IOMMU_VQ_MAX);

	f->private_data = vi;

	return 0;
}

static int vhost_iommu_release(struct inode *inode, struct file *f)
{
	struct vhost_iommu *vi = f->private_data;

	vhost_iommu_stop(vi, &vi->vq_req);
	vhost_iommu_stop(vi, &vi->vq_evt);
	vhost_iommu_flush(vi);
	vhost_dev_stop(&vi->dev);
	vhost_dev_cleanup(&vi->dev);
	vhost_iommu_deregister(vi->iommu_fd);
	/* Make sure no callbacks are outstanding */
	synchronize_rcu_bh();
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_iommu_flush(vi);
	kfree(vi->dev.vqs);
	kvfree(vi);
	return 0;
}

#ifdef CONFIG_COMPAT
static long vhost_iommu_compat_ioctl(struct file *f, unsigned int ioctl,
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
