// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio driver for the paravirtualized IOMMU
 *
 * Copyright (C) 2018 Arm Limited
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/amba/bus.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/freezer.h>
#include <linux/interval_tree.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/wait.h>

#include <uapi/linux/virtio_iommu.h>

#define CREATE_TRACE_POINTS
#include <trace/events/virtio_iommu.h>

#include "iommu-pasid-table.h"

#define MSI_IOVA_BASE			0x8000000
#define MSI_IOVA_LENGTH			0x100000

#define VIOMMU_REQUEST_VQ		0
#define VIOMMU_EVENT_VQ			1
#define VIOMMU_NR_VQS			2

#define VIOMMU_REQUEST_TIMEOUT		10000 /* 10s */

/* Some architectures need an Address Space ID for each page table */
static DEFINE_IDA(asid_ida);

struct viommu_dev {
	struct iommu_device		iommu;
	struct device			*dev;
	struct virtio_device		*vdev;

	struct ida			domain_ids;

	struct virtqueue		*vqs[VIOMMU_NR_VQS];
	spinlock_t			request_lock;
	struct list_head		requests;
	void				*evts;

	/* Device configuration */
	struct iommu_domain_geometry	geometry;
	u64				pgsize_bitmap;
	u8				domain_bits;
	u32				probe_size;

	bool				has_table:1;
	bool				has_map:1;
};

struct viommu_mapping {
	phys_addr_t			paddr;
	struct interval_tree_node	iova;
	u32				flags;
};

struct viommu_domain {
	struct iommu_domain		domain;
	struct viommu_dev		*viommu;
	struct mutex			mutex;
	unsigned int			id;

	struct iommu_pasid_table_ops	*pasid_ops;
	struct iommu_pasid_table_cfg	pasid_cfg;

	/* PASID 0 is always used for IOVA */
	struct io_pgtable_ops		*pgtable_ops;
	struct io_pgtable_cfg		pgtable_cfg;
	struct iommu_pasid_entry	*pgtable_entry;

	/* When no table is bound, use generic mappings */
	spinlock_t			mappings_lock;
	struct rb_root_cached		mappings;

	unsigned long			nr_endpoints;
};

#define vdev_for_each_id(i, eid, vdev)					\
	for (i = 0; i < vdev->dev->iommu_fwspec->num_ids &&		\
	            ({ eid = vdev->dev->iommu_fwspec->ids[i]; 1; }); i++)

struct viommu_endpoint {
	struct device			*dev;
	struct viommu_dev		*viommu;
	struct viommu_domain		*vdomain;
	struct list_head		resv_regions;
	struct list_head		identity_regions;
	struct device_link		*link;

	/* properties of the physical IOMMU */
	u64				pgsize_mask;
	u64				input_start;
	u64				input_end;
	u8				output_bits;
	u8				pasid_bits;
	/* Preferred PASID table format */
	void				*pstf;
	/* Preferred page table format */
	void				*pgtf;
};

struct viommu_request {
	struct list_head		list;
	void				*writeback;
	unsigned int			write_offset;
	unsigned int			len;
	char				buf[];
};

#define VIOMMU_FAULT_RESV_MASK		0xffffff00

struct viommu_event {
	union {
		u32			head;
		struct virtio_iommu_fault fault;
	};
};

#define to_viommu_domain(domain)	\
	container_of(domain, struct viommu_domain, domain)

static int viommu_get_req_errno(void *buf, size_t len)
{
	struct virtio_iommu_req_tail *tail = buf + len - sizeof(*tail);

	switch (tail->status) {
	case VIRTIO_IOMMU_S_OK:
		return 0;
	case VIRTIO_IOMMU_S_UNSUPP:
		return -ENOSYS;
	case VIRTIO_IOMMU_S_INVAL:
		return -EINVAL;
	case VIRTIO_IOMMU_S_RANGE:
		return -ERANGE;
	case VIRTIO_IOMMU_S_NOENT:
		return -ENOENT;
	case VIRTIO_IOMMU_S_FAULT:
		return -EFAULT;
	case VIRTIO_IOMMU_S_IOERR:
	case VIRTIO_IOMMU_S_DEVERR:
	default:
		return -EIO;
	}
}

static void viommu_set_req_status(void *buf, size_t len, int status)
{
	struct virtio_iommu_req_tail *tail = buf + len - sizeof(*tail);

	tail->status = status;
}

static off_t viommu_get_req_offset(struct viommu_dev *viommu,
				   struct virtio_iommu_req_head *req,
				   size_t len)
{
	size_t tail_size = sizeof(struct virtio_iommu_req_tail);

	if (req->type == VIRTIO_IOMMU_T_PROBE)
		return len - viommu->probe_size - tail_size;

	return len - tail_size;
}

/*
 * __viommu_sync_req - Complete all in-flight requests
 *
 * Wait for all added requests to complete. When this function returns, all
 * requests that were in-flight at the time of the call have completed.
 */
static int __viommu_sync_req(struct viommu_dev *viommu)
{
	int ret = 0;
	unsigned int len;
	size_t write_len;
	struct viommu_request *req;
	struct virtqueue *vq = viommu->vqs[VIOMMU_REQUEST_VQ];
	ktime_t timeout = ktime_add_ms(ktime_get(), VIOMMU_REQUEST_TIMEOUT);

	assert_spin_locked(&viommu->request_lock);

	virtqueue_kick(vq);

	while (!list_empty(&viommu->requests)) {
		len = 0;
		req = virtqueue_get_buf(vq, &len);
		if (req == NULL) {
			if (ktime_before(ktime_get(), timeout))
				continue;

			/* After timeout, remove all requests */
			req = list_first_entry(&viommu->requests,
					       struct viommu_request, list);
			ret = -ETIMEDOUT;
		}

		if (!len)
			viommu_set_req_status(req->buf, req->len,
					      VIRTIO_IOMMU_S_IOERR);

		write_len = req->len - req->write_offset;
		if (req->writeback && len >= write_len)
			memcpy(req->writeback, req->buf + req->write_offset,
			       write_len);

		list_del(&req->list);
		kfree(req);
	}

	return ret;
}

static int viommu_sync_req(struct viommu_dev *viommu)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&viommu->request_lock, flags);
	ret = __viommu_sync_req(viommu);
	if (ret)
		dev_dbg(viommu->dev, "could not sync requests (%d)\n", ret);
	spin_unlock_irqrestore(&viommu->request_lock, flags);

	return ret;
}

/*
 * __viommu_add_request - Add one request to the queue
 * @buf: pointer to the request buffer
 * @len: length of the request buffer
 * @writeback: copy data back to the buffer when the request completes.
 *
 * Add a request to the queue. Only synchronize the queue if it's already full.
 * Otherwise don't kick the queue nor wait for requests to complete.
 *
 * When @writeback is true, data written by the device, including the request
 * status, is copied into @buf after the request completes. This is unsafe if
 * the caller allocates @buf on stack and drops the lock between add_req() and
 * sync_req().
 *
 * Return 0 if the request was successfully added to the queue.
 */
static int __viommu_add_req(struct viommu_dev *viommu, void *buf, size_t len,
			    bool writeback)
{
	int ret;
	off_t write_offset;
	struct viommu_request *req;
	struct scatterlist top_sg, bottom_sg;
	struct scatterlist *sg[2] = { &top_sg, &bottom_sg };
	struct virtqueue *vq = viommu->vqs[VIOMMU_REQUEST_VQ];

	assert_spin_locked(&viommu->request_lock);

	write_offset = viommu_get_req_offset(viommu, buf, len);
	if (!write_offset)
		return -EINVAL;

	req = kzalloc(sizeof(*req) + len, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	req->len = len;
	if (writeback) {
		req->writeback = buf + write_offset;
		req->write_offset = write_offset;
	}
	memcpy(&req->buf, buf, write_offset);

	sg_init_one(&top_sg, req->buf, write_offset);
	sg_init_one(&bottom_sg, req->buf + write_offset, len - write_offset);

	ret = virtqueue_add_sgs(vq, sg, 1, 1, req, GFP_ATOMIC);
	if (ret == -ENOSPC) {
		/* If the queue is full, sync and retry */
		if (!__viommu_sync_req(viommu))
			ret = virtqueue_add_sgs(vq, sg, 1, 1, req, GFP_ATOMIC);
	}
	if (ret)
		goto err_free;

	list_add_tail(&req->list, &viommu->requests);
	return 0;

err_free:
	kfree(req);
	return ret;
}

static int viommu_add_req(struct viommu_dev *viommu, void *buf, size_t len)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&viommu->request_lock, flags);
	ret = __viommu_add_req(viommu, buf, len, false);
	if (ret)
		dev_dbg(viommu->dev, "could not add request: %d\n", ret);
	spin_unlock_irqrestore(&viommu->request_lock, flags);

	return ret;
}

/*
 * Send a request and wait for it to complete. Return the request status (as an
 * errno)
 */
static int viommu_send_req_sync(struct viommu_dev *viommu, void *buf,
				size_t len)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&viommu->request_lock, flags);

	ret = __viommu_add_req(viommu, buf, len, true);
	if (ret) {
		dev_dbg(viommu->dev, "could not add request (%d)\n", ret);
		goto out_unlock;
	}

	ret = __viommu_sync_req(viommu);
	if (ret) {
		dev_dbg(viommu->dev, "could not sync requests (%d)\n", ret);
		/* Fall-through (get the actual request status) */
	}

	ret = viommu_get_req_errno(buf, len);
out_unlock:
	spin_unlock_irqrestore(&viommu->request_lock, flags);
	return ret;
}

/*
 * viommu_add_mapping - add a mapping to the internal tree
 *
 * On success, return the new mapping. Otherwise return NULL.
 */
static struct viommu_mapping *
viommu_add_mapping(struct viommu_domain *vdomain, unsigned long iova,
		   phys_addr_t paddr, size_t size, u32 flags)
{
	unsigned long irqflags;
	struct viommu_mapping *mapping;

	mapping = kzalloc(sizeof(*mapping), GFP_ATOMIC);
	if (!mapping)
		return NULL;

	mapping->paddr		= paddr;
	mapping->iova.start	= iova;
	mapping->iova.last	= iova + size - 1;
	mapping->flags		= flags;

	spin_lock_irqsave(&vdomain->mappings_lock, irqflags);
	interval_tree_insert(&mapping->iova, &vdomain->mappings);
	spin_unlock_irqrestore(&vdomain->mappings_lock, irqflags);

	return mapping;
}

/*
 * viommu_del_mappings - remove mappings from the internal tree
 *
 * @vdomain: the domain
 * @iova: start of the range
 * @size: size of the range. A size of 0 corresponds to the entire address
 *	space.
 *
 * On success, returns the number of unmapped bytes (>= size)
 */
static size_t viommu_del_mappings(struct viommu_domain *vdomain,
				  unsigned long iova, size_t size)
{
	size_t unmapped = 0;
	unsigned long flags;
	unsigned long last = iova + size - 1;
	struct viommu_mapping *mapping = NULL;
	struct interval_tree_node *node, *next;

	spin_lock_irqsave(&vdomain->mappings_lock, flags);
	next = interval_tree_iter_first(&vdomain->mappings, iova, last);
	while (next) {
		node = next;
		mapping = container_of(node, struct viommu_mapping, iova);
		next = interval_tree_iter_next(node, iova, last);

		/* Trying to split a mapping? */
		if (mapping->iova.start < iova)
			break;

		/*
		 * Note that for a partial range, this will return the full
		 * mapping so we avoid sending split requests to the device.
		 */
		unmapped += mapping->iova.last - mapping->iova.start + 1;

		interval_tree_remove(node, &vdomain->mappings);
		kfree(mapping);
	}
	spin_unlock_irqrestore(&vdomain->mappings_lock, flags);

	return unmapped;
}

/*
 * viommu_replay_mappings - re-send MAP requests
 *
 * When reattaching a domain that was previously detached from all endpoints,
 * mappings were deleted from the device. Re-create the mappings available in
 * the internal tree.
 */
static int viommu_replay_mappings(struct viommu_domain *vdomain)
{
	int ret;
	unsigned long flags;
	struct viommu_mapping *mapping;
	struct interval_tree_node *node;
	struct virtio_iommu_req_map map;

	spin_lock_irqsave(&vdomain->mappings_lock, flags);
	node = interval_tree_iter_first(&vdomain->mappings, 0, -1UL);
	while (node) {
		mapping = container_of(node, struct viommu_mapping, iova);
		map = (struct virtio_iommu_req_map) {
			.head.type	= VIRTIO_IOMMU_T_MAP,
			.domain		= cpu_to_le32(vdomain->id),
			.virt_start	= cpu_to_le64(mapping->iova.start),
			.virt_end	= cpu_to_le64(mapping->iova.last),
			.phys_start	= cpu_to_le64(mapping->paddr),
			.flags		= cpu_to_le32(mapping->flags),
		};

		ret = viommu_send_req_sync(vdomain->viommu, &map, sizeof(map));
		if (ret)
			break;

		node = interval_tree_iter_next(node, 0, -1UL);
	}
	spin_unlock_irqrestore(&vdomain->mappings_lock, flags);

	return ret;
}

static int viommu_add_resv_mem(struct viommu_endpoint *vdev,
			       struct virtio_iommu_probe_resv_mem *mem,
			       size_t len)
{
	struct iommu_resv_region *region = NULL;
	unsigned long prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;
	unsigned long flags;

	u64 start = le64_to_cpu(mem->start);
	u64 end = le64_to_cpu(mem->end);
	size_t size = end - start + 1;

	if (len < sizeof(*mem))
		return -EINVAL;

	switch (mem->subtype) {
	default:
		dev_warn(vdev->dev, "unknown resv mem subtype 0x%x\n",
			 mem->subtype);
		/* Fall-through */
	case VIRTIO_IOMMU_RESV_MEM_T_RESERVED:
		region = iommu_alloc_resv_region(start, size, 0,
						 IOMMU_RESV_RESERVED);
		break;
	case VIRTIO_IOMMU_RESV_MEM_T_MSI:
		region = iommu_alloc_resv_region(start, size, prot,
						 IOMMU_RESV_MSI);
		break;
	case VIRTIO_IOMMU_RESV_MEM_T_IDENTITY:
		flags = le32_to_cpu(mem->flags);
		prot = (flags & VIRTIO_IOMMU_MAP_F_READ ? IOMMU_READ : 0) |
		       (flags & VIRTIO_IOMMU_MAP_F_WRITE ? IOMMU_WRITE : 0) |
		       (flags & VIRTIO_IOMMU_MAP_F_MMIO ? IOMMU_MMIO : 0) |
		       (flags & VIRTIO_IOMMU_MAP_F_EXEC ? 0 : IOMMU_NOEXEC);
		region = iommu_alloc_resv_region(start, size, prot,
						 IOMMU_RESV_DIRECT);
		break;
	}

	list_add(&region->list, region->type == IOMMU_RESV_DIRECT ?
		 &vdev->identity_regions : &vdev->resv_regions);
	return 0;
}

static int viommu_add_pgsize_mask(struct viommu_endpoint *vdev,
				  struct virtio_iommu_probe_page_size_mask *prop,
				  size_t len)
{
	if (len < sizeof(*prop))
		return -EINVAL;
	vdev->pgsize_mask = le64_to_cpu(prop->mask);
	return 0;
}

static int viommu_add_input_range(struct viommu_endpoint *vdev,
				  struct virtio_iommu_probe_input_range *prop,
				  size_t len)
{
	if (len < sizeof(*prop))
		return -EINVAL;
	vdev->input_start	= le64_to_cpu(prop->start);
	vdev->input_end		= le64_to_cpu(prop->end);
	return 0;
}

static int viommu_add_output_size(struct viommu_endpoint *vdev,
				  struct virtio_iommu_probe_output_size *prop,
				  size_t len)
{
	if (len < sizeof(*prop))
		return -EINVAL;
	vdev->output_bits = prop->bits;
	return 0;
}

static int viommu_add_pasid_size(struct viommu_endpoint *vdev,
				 struct virtio_iommu_probe_pasid_size *prop,
				 size_t len)
{
	if (len < sizeof(*prop))
		return -EINVAL;
	vdev->pasid_bits = prop->bits;
	return 0;
}

static int viommu_add_pgtf(struct viommu_endpoint *vdev, void *pgtf, size_t len)
{
	/* Select the first page table format available */
	if (len < sizeof(struct virtio_iommu_probe_table_format) || vdev->pgtf)
		return -EINVAL;

	vdev->pgtf = kmemdup(pgtf, len, GFP_KERNEL);
	if (!vdev->pgtf)
		return -ENOMEM;

	return 0;
}

static int viommu_add_pstf(struct viommu_endpoint *vdev, void *pstf, size_t len)
{
	if (len < sizeof(struct virtio_iommu_probe_table_format) || vdev->pstf)
		return -EINVAL;

	vdev->pstf = kmemdup(pstf, len, GFP_KERNEL);
	if (!vdev->pstf)
		return -ENOMEM;

	return 0;
}

static int viommu_probe_endpoint(struct viommu_dev *viommu, struct device *dev)
{
	int ret;
	u16 type, len;
	size_t cur = 0;
	size_t probe_len;
	struct virtio_iommu_req_probe *probe;
	struct virtio_iommu_probe_property *prop;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct viommu_endpoint *vdev = fwspec->iommu_priv;

	if (!fwspec->num_ids)
		return -EINVAL;

	probe_len = sizeof(*probe) + viommu->probe_size +
		    sizeof(struct virtio_iommu_req_tail);
	probe = kzalloc(probe_len, GFP_KERNEL);
	if (!probe)
		return -ENOMEM;

	probe->head.type = VIRTIO_IOMMU_T_PROBE;
	/*
	 * For now, assume that properties of an endpoint that outputs multiple
	 * IDs are consistent. Only probe the first one.
	 */
	probe->endpoint = cpu_to_le32(fwspec->ids[0]);

	ret = viommu_send_req_sync(viommu, probe, probe_len);
	if (ret)
		goto out_free;

	prop = (void *)probe->properties;
	type = le16_to_cpu(prop->type) & VIRTIO_IOMMU_PROBE_T_MASK;

	while (type != VIRTIO_IOMMU_PROBE_T_NONE &&
	       cur < viommu->probe_size) {
		void *value = prop;
		len = le16_to_cpu(prop->length) + sizeof(*prop);

		switch (type) {
		case VIRTIO_IOMMU_PROBE_T_RESV_MEM:
			ret = viommu_add_resv_mem(vdev, value, len);
			break;
		case VIRTIO_IOMMU_PROBE_T_PAGE_SIZE_MASK:
			ret = viommu_add_pgsize_mask(vdev, value, len);
			break;
		case VIRTIO_IOMMU_PROBE_T_INPUT_RANGE:
			ret = viommu_add_input_range(vdev, value, len);
			break;
		case VIRTIO_IOMMU_PROBE_T_OUTPUT_SIZE:
			ret = viommu_add_output_size(vdev, value, len);
			break;
		case VIRTIO_IOMMU_PROBE_T_PASID_SIZE:
			ret = viommu_add_pasid_size(vdev, value, len);
			break;
		case VIRTIO_IOMMU_PROBE_T_PAGE_TABLE_FMT:
			ret = viommu_add_pgtf(vdev, value, len);
			break;
		case VIRTIO_IOMMU_PROBE_T_PASID_TABLE_FMT:
			ret = viommu_add_pstf(vdev, value, len);
			break;
		default:
			dev_err(dev, "unknown viommu prop 0x%x\n", type);
		}

		if (ret)
			dev_err(dev, "failed to parse viommu prop 0x%x\n", type);

		cur += len;
		if (cur >= viommu->probe_size)
			break;

		prop = (void *)probe->properties + cur;
		type = le16_to_cpu(prop->type) & VIRTIO_IOMMU_PROBE_T_MASK;
	}

out_free:
	kfree(probe);
	return ret;
}

static int viommu_fault_handler(struct viommu_dev *viommu,
				struct virtio_iommu_fault *fault)
{
	char *reason_str;

	u8 reason	= fault->reason;
	u32 flags	= le32_to_cpu(fault->flags);
	u32 endpoint	= le32_to_cpu(fault->endpoint);
	u64 address	= le64_to_cpu(fault->address);

	switch (reason) {
	case VIRTIO_IOMMU_FAULT_R_DOMAIN:
		reason_str = "domain";
		break;
	case VIRTIO_IOMMU_FAULT_R_MAPPING:
		reason_str = "page";
		break;
	case VIRTIO_IOMMU_FAULT_R_UNKNOWN:
	default:
		reason_str = "unknown";
		break;
	}

	/* TODO: find EP by ID and report_iommu_fault */
	if (flags & VIRTIO_IOMMU_FAULT_F_ADDRESS)
		dev_err_ratelimited(viommu->dev, "%s fault from EP %u at %#llx [%s%s%s]\n",
				    reason_str, endpoint, address,
				    flags & VIRTIO_IOMMU_FAULT_F_READ ? "R" : "",
				    flags & VIRTIO_IOMMU_FAULT_F_WRITE ? "W" : "",
				    flags & VIRTIO_IOMMU_FAULT_F_EXEC ? "X" : "");
	else
		dev_err_ratelimited(viommu->dev, "%s fault from EP %u\n",
				    reason_str, endpoint);
	return 0;
}

static void viommu_event_handler(struct virtqueue *vq)
{
	int ret;
	unsigned int len;
	struct scatterlist sg[1];
	struct viommu_event *evt;
	struct viommu_dev *viommu = vq->vdev->priv;

	while ((evt = virtqueue_get_buf(vq, &len)) != NULL) {
		if (len > sizeof(*evt)) {
			dev_err(viommu->dev,
				"invalid event buffer (len %u != %zu)\n",
				len, sizeof(*evt));
		} else if (!(evt->head & VIOMMU_FAULT_RESV_MASK)) {
			viommu_fault_handler(viommu, &evt->fault);
		}

		sg_init_one(sg, evt, sizeof(*evt));
		ret = virtqueue_add_inbuf(vq, sg, 1, evt, GFP_ATOMIC);
		if (ret)
			dev_err(viommu->dev, "could not add event buffer\n");
	}

	if (!virtqueue_kick(vq))
		dev_err(viommu->dev, "kick failed\n");
}

/* PASID and pgtable APIs */

static void __viommu_flush_pasid_tlb_all(struct viommu_domain *vdomain,
					 int pasid, u64 tag)
{
	struct virtio_iommu_req_invalidate req = {
		.head.type	= VIRTIO_IOMMU_T_INVALIDATE,
		.scope		= cpu_to_le32(VIRTIO_IOMMU_INVAL_S_PASID),

		.domain		= cpu_to_le32(vdomain->id),
		.pasid		= cpu_to_le32(pasid),
		.id		= cpu_to_le64(tag),
	};

	if (viommu_send_req_sync(vdomain->viommu, &req, sizeof(req)))
		pr_debug("could not send invalidate request\n");
}

static void viommu_flush_pasid_tlb_all(void *cookie, int pasid,
				       struct iommu_pasid_entry *entry)
{
	__viommu_flush_pasid_tlb_all(cookie, pasid, entry->tag);
}

static void viommu_flush_pasid(void *cookie, int pasid, bool leaf)
{
	struct viommu_domain *vdomain = cookie;
	struct virtio_iommu_req_invalidate req = {
		.head.type	= VIRTIO_IOMMU_T_INVALIDATE,
		.scope		= cpu_to_le32(VIRTIO_IOMMU_INVAL_S_PASID),
		.flags		= cpu_to_le32(VIRTIO_IOMMU_INVAL_F_CONFIG),

		.domain		= cpu_to_le32(vdomain->id),
		.pasid		= cpu_to_le32(pasid),
	};

	if (viommu_send_req_sync(vdomain->viommu, &req, sizeof(req)))
		pr_debug("could not send invalidate request\n");
}

static void viommu_flush_pasid_all(void *cookie)
{
	struct viommu_domain *vdomain = cookie;
	struct virtio_iommu_req_invalidate req = {
		.head.type	= VIRTIO_IOMMU_T_INVALIDATE,
		.scope		= cpu_to_le32(VIRTIO_IOMMU_INVAL_S_DOMAIN),
		.flags		= cpu_to_le32(VIRTIO_IOMMU_INVAL_F_CONFIG),

		.domain		= cpu_to_le32(vdomain->id),
	};

	if (!vdomain->nr_endpoints)
		return;

	if (viommu_send_req_sync(vdomain->viommu, &req, sizeof(req)))
		pr_debug("could not send invalidate request\n");
}

static struct iommu_pasid_sync_ops viommu_pasid_sync_ops = {
	.cfg_flush		= viommu_flush_pasid,
	.cfg_flush_all		= viommu_flush_pasid_all,
	.tlb_flush		= viommu_flush_pasid_tlb_all,
};

static void viommu_flush_tlb_all(void *cookie)
{
	struct viommu_domain *vdomain = cookie;

	if (!vdomain->pgtable_entry)
		return;
	__viommu_flush_pasid_tlb_all(vdomain, 0, vdomain->pgtable_entry->tag);
}

static void viommu_flush_tlb_add(unsigned long iova, size_t size,
				 size_t granule, bool leaf, void *cookie)
{
	struct viommu_domain *vdomain = cookie;
	struct virtio_iommu_req_invalidate req = {
		.head.type	= VIRTIO_IOMMU_T_INVALIDATE,
		.scope		= cpu_to_le32(VIRTIO_IOMMU_INVAL_S_VA),
		.flags		= cpu_to_le32(leaf ? VIRTIO_IOMMU_INVAL_F_LEAF : 0),

		.domain		= cpu_to_le32(vdomain->id),
		.pasid		= 0,
		.id		= cpu_to_le64(vdomain->pgtable_entry->tag),
		.virt_start	= cpu_to_le64(iova),
		.nr_pages	= cpu_to_le64(size / granule),
		.granule	= ilog2(granule),
	};

	if (viommu_add_req(vdomain->viommu, &req, sizeof(req)))
		pr_debug("could not add invalidate request\n");
}

static void viommu_flush_tlb_sync(void *cookie)
{
	struct viommu_domain *vdomain = cookie;

	viommu_sync_req(vdomain->viommu);
}

static struct iommu_gather_ops viommu_gather_ops = {
	.tlb_flush_all		= viommu_flush_tlb_all,
	.tlb_add_flush		= viommu_flush_tlb_add,
	.tlb_sync		= viommu_flush_tlb_sync,
};

/* IOMMU API */

static struct iommu_domain *viommu_domain_alloc(unsigned type)
{
	struct viommu_domain *vdomain;

	if (type != IOMMU_DOMAIN_UNMANAGED && type != IOMMU_DOMAIN_DMA)
		return NULL;

	vdomain = kzalloc(sizeof(*vdomain), GFP_KERNEL);
	if (!vdomain)
		return NULL;

	mutex_init(&vdomain->mutex);
	spin_lock_init(&vdomain->mappings_lock);
	vdomain->mappings = RB_ROOT_CACHED;

	if (type == IOMMU_DOMAIN_DMA &&
	    iommu_get_dma_cookie(&vdomain->domain)) {
		kfree(vdomain);
		return NULL;
	}

	return &vdomain->domain;
}

static int viommu_domain_finalise(struct viommu_endpoint *vdev,
				  struct iommu_domain *domain)
{
	int ret;
	struct viommu_dev *viommu = vdev->viommu;
	struct viommu_domain *vdomain = to_viommu_domain(domain);
	/* ida limits size to 31 bits. A value of 0 means "max" */
	unsigned int max_domain = viommu->domain_bits >= 31 ? 0 :
				  1U << viommu->domain_bits;

	vdomain->viommu		= viommu;

	domain->pgsize_bitmap	= viommu->pgsize_bitmap;
	domain->geometry	= viommu->geometry;

	ret = ida_simple_get(&viommu->domain_ids, 0, max_domain, GFP_KERNEL);
	if (ret >= 0)
		vdomain->id = (unsigned int)ret;

	return ret > 0 ? 0 : ret;
}

__maybe_unused
static int viommu_dma_init_domain(struct iommu_domain *domain,
				  struct device *dev)
{
	u64 base = domain->geometry.aperture_start;
	/* Doesn't support 64-bits IOVA, so restrict it to 63 */
	size_t size = min_t(size_t, -1UL - 1,
			    domain->geometry.aperture_end - base) + 1;

	return iommu_dma_init_domain(domain, base, size, dev);
}

static void viommu_domain_free(struct iommu_domain *domain)
{
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	iommu_put_dma_cookie(domain);

	/* Free all remaining mappings (size 2^64) */
	viommu_del_mappings(vdomain, 0, 0);

	if (vdomain->viommu)
		ida_simple_remove(&vdomain->viommu->domain_ids, vdomain->id);
	if (vdomain->pasid_ops)
		iommu_free_pasid_ops(vdomain->pasid_ops);
	if (vdomain->pgtable_ops)
		free_io_pgtable_ops(vdomain->pgtable_ops);

	kfree(vdomain);
}

static int viommu_prepare_arm_pgt(void *properties,
				  struct io_pgtable_cfg *cfg)
{
	struct virtio_iommu_probe_pgtf_arm *pgtf = properties;
	u64 float_mask = (VIRTIO_IOMMU_PGTF_ARM_LPAE_F_HPD |
			  VIRTIO_IOMMU_PGTF_ARM_LPAE_F_HW_ACCESS |
			  VIRTIO_IOMMU_PGTF_ARM_LPAE_F_HW_FLOAT);
	u64 flags = le64_to_cpu(pgtf->flags);

	if ((flags & float_mask) == float_mask) {
		pr_info("FLOAT BIT");
		cfg->quirks |= IO_PGTABLE_QUIRK_FLOAT_BIT;
	}

	return 0;
}

#define ARM_LPAE_TCR_MASK	\
	(VIRTIO_IOMMU_PGTF_ARM_TG0_MASK << VIRTIO_IOMMU_PGTF_ARM_TG0_SHIFT |\
	 VIRTIO_IOMMU_PGTF_ARM_IRGN0_MASK << VIRTIO_IOMMU_PGTF_ARM_IRGN0_SHIFT |\
	 VIRTIO_IOMMU_PGTF_ARM_ORGN0_MASK << VIRTIO_IOMMU_PGTF_ARM_ORGN0_SHIFT |\
	 VIRTIO_IOMMU_PGTF_ARM_SH0_MASK << VIRTIO_IOMMU_PGTF_ARM_SH0_SHIFT |\
	 VIRTIO_IOMMU_PGTF_ARM_TG0_MASK << VIRTIO_IOMMU_PGTF_ARM_TG0_SHIFT)

static int viommu_config_arm_pgt(struct viommu_endpoint *vdev,
				 struct io_pgtable_cfg *cfg,
				 struct virtio_iommu_req_attach_pgt_arm *req,
				 u64 *asid)
{
	struct virtio_iommu_probe_pgtf_arm *pgtf = (void *)vdev->pgtf;
	u64 tcr = (cfg->arm_lpae_s1_cfg.tcr & ARM_LPAE_TCR_MASK) |
		  VIRTIO_IOMMU_PGTF_ARM_EPD1 | VIRTIO_IOMMU_PGTF_ARM_HPD0 |
		  VIRTIO_IOMMU_PGTF_ARM_HA | VIRTIO_IOMMU_PGTF_ARM_HPD1 |
		  VIRTIO_IOMMU_PGTF_ARM_HWU059;
	int id;

	if (pgtf->asid_bits != 8 && pgtf->asid_bits != 16)
		return -EINVAL;

	id = ida_simple_get(&asid_ida, 1, 1 << pgtf->asid_bits, GFP_KERNEL);
	if (id < 0)
		return -ENOMEM;

	req->format	= cpu_to_le16(VIRTIO_IOMMU_PGTF_ARM_LPAE);
	req->ttbr0	= cpu_to_le64(cfg->arm_lpae_s1_cfg.ttbr[0]);
	req->tcr	= cpu_to_le64(tcr);
	req->mair	= cpu_to_le64(cfg->arm_lpae_s1_cfg.mair[0]);
	req->asid	= cpu_to_le16(id);

	*asid = id;
	return 0;
}

static int viommu_attach_pgtable(struct viommu_endpoint *vdev,
				 struct viommu_domain *vdomain,
				 enum io_pgtable_fmt fmt,
				 struct io_pgtable_cfg *cfg,
				 u64 *asid)
{
	int ret;
	int i, eid;

	struct virtio_iommu_req_attach_table req = {
		.head.type	= VIRTIO_IOMMU_T_ATTACH_TABLE,
		.domain		= cpu_to_le32(vdomain->id),
	};

	switch (fmt) {
	case ARM_64_LPAE_S1:
		ret = viommu_config_arm_pgt(vdev, cfg, (void *)&req, asid);
		if (ret)
			return ret;
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}

	vdev_for_each_id(i, eid, vdev) {
		req.endpoint = cpu_to_le32(eid);
		ret = viommu_send_req_sync(vdomain->viommu, &req, sizeof(req));
		if (ret)
			return ret;
	}

	return 0;
}

static int viommu_setup_pgtable(struct viommu_endpoint *vdev,
				struct viommu_domain *vdomain)
{
	int ret;
	enum io_pgtable_fmt fmt;
	struct iommu_pasid_entry *entry;
	struct io_pgtable_ops *ops = NULL;
	struct viommu_dev *viommu = vdev->viommu;
	struct iommu_pasid_table_ops *pasid_ops = vdomain->pasid_ops;
	struct virtio_iommu_probe_table_format *desc = vdev->pgtf;
	struct io_pgtable_cfg cfg = {
		.iommu_dev	= viommu->dev->parent,
		.tlb		= &viommu_gather_ops,
		.pgsize_bitmap	= vdev->pgsize_mask ? vdev->pgsize_mask :
				  vdomain->domain.pgsize_bitmap,
		.ias		= (vdev->input_end ? ilog2(vdev->input_end) :
				   ilog2(vdomain->domain.geometry.aperture_end)) + 1,
		.oas		= vdev->output_bits,
	};

	if (!desc)
		return -EINVAL;

	if (!vdev->output_bits)
		return -ENODEV;

	switch (le16_to_cpu(desc->format)) {
	case VIRTIO_IOMMU_PGTF_ARM_LPAE:
		fmt = ARM_64_LPAE_S1;
		ret = viommu_prepare_arm_pgt(vdev->pgtf, &cfg);
		break;
	default:
		ret = -EINVAL;
		dev_err(vdev->dev, "unsupported page table format 0x%x\n",
			le16_to_cpu(desc->format));
	}
	if (ret)
		return ret;

	if (vdomain->pgtable_ops)
		/* TODO Sanity-check cfg */
		return -ENOSYS;

	ops = alloc_io_pgtable_ops(fmt, &cfg, vdomain);
	if (!ops) {
		pr_err("alloc failed\n");
		return -ENOMEM;
	}

	if (!pasid_ops) {
		/* No PASID support, send attach_table, create a dummy entry */
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry)
			goto err_free_pgtable;

		ret = viommu_attach_pgtable(vdev, vdomain, fmt, &cfg,
					    &entry->tag);
		if (ret) {
			kfree(entry);
			goto err_free_pgtable;
		}
	} else {
		entry = pasid_ops->alloc_priv_entry(pasid_ops, fmt, &cfg);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry);
			goto err_free_pgtable;
		}

		ret = pasid_ops->set_entry(pasid_ops, 0, entry);
		if (ret) {
			iommu_free_pasid_entry(entry);
			goto err_free_pgtable;
		}
	}

	vdomain->pgtable_entry = entry;
	vdomain->pgtable_ops = ops;
	vdomain->pgtable_cfg = cfg;

	dev_dbg(vdev->dev, "using page table format 0x%x\n", fmt);

	return 0;

err_free_pgtable:
	free_io_pgtable_ops(ops);
	return ret;
}

static int viommu_teardown_pgtable(struct viommu_domain *vdomain)
{
	struct iommu_pasid_table_ops *pasid_ops = vdomain->pasid_ops;

	if (!vdomain->pgtable_ops)
		return 0;

	if (pasid_ops) {
		pasid_ops->clear_entry(pasid_ops, 0, vdomain->pgtable_entry);
		iommu_free_pasid_entry(vdomain->pgtable_entry);
	} else {
		struct iommu_pasid_entry *entry = vdomain->pgtable_entry;

		if (entry->tag)
			ida_simple_remove(&asid_ida, entry->tag);
		kfree(entry);
	}

	free_io_pgtable_ops(vdomain->pgtable_ops);
	vdomain->pgtable_ops = NULL;
	vdomain->pgtable_entry = NULL;

	return 0;
}

static int viommu_prepare_arm_pst(struct viommu_endpoint *vdev,
				  struct iommu_pasid_table_cfg *cfg)
{
	struct virtio_iommu_probe_pstf_arm *pstf = vdev->pstf;
	struct virtio_iommu_probe_pgtf_arm *pgtf = vdev->pgtf;
	u64 pgflags = le64_to_cpu(pgtf->flags);
	u64 flags = le64_to_cpu(pstf->flags);

	bool hw_dirty = pgflags & VIRTIO_IOMMU_PGTF_ARM_LPAE_F_HW_DIRTY;
	bool hw_access = pgflags & VIRTIO_IOMMU_PGTF_ARM_LPAE_F_HW_ACCESS;

	bool stall = !dev_is_pci(vdev->dev) && flags &
		     (VIRTIO_IOMMU_PSTF_ARM_SV3_F_STALL_FORCE |
		      VIRTIO_IOMMU_PSTF_ARM_SV3_F_STALL);

	/* Some sanity checks */
	if (pgtf->asid_bits != 8 && pgtf->asid_bits != 16)
		return -EINVAL;

	cfg->arm_smmu = (struct arm_smmu_context_cfg) {
		.stall		= stall,
		.hw_dirty	= hw_dirty,
		.hw_access	= hw_access,
		.asid_bits	= pgtf->asid_bits,
	};
	return 0;
}

static int viommu_config_arm_pst(struct iommu_pasid_table_cfg *cfg,
				 struct virtio_iommu_req_attach_pst_arm *req)
{
	req->format		= cpu_to_le16(VIRTIO_IOMMU_PSTF_ARM_SV3);
	req->s1fmt		= cfg->arm_smmu.s1fmt;
	req->s1dss		= VIRTIO_IOMMU_PSTF_ARM_SV3_DSS_0;
	req->s1contextptr	= cpu_to_le64(cfg->base);
	req->s1cdmax		= cpu_to_le32(cfg->order);
	return 0;
}

static int viommu_bind_pasid_table(struct viommu_endpoint *vdev,
				   struct viommu_domain *vdomain)
{
	int ret;
	int i, eid;
	enum iommu_pasid_table_fmt fmt;
	struct iommu_pasid_table_ops *ops = NULL;
	struct virtio_iommu_probe_table_format *desc = vdev->pstf;
	struct virtio_iommu_req_attach_table req = {
		.head.type	= VIRTIO_IOMMU_T_ATTACH_TABLE,
		.domain		= cpu_to_le32(vdomain->id),
	};
	struct viommu_dev *viommu = vdev->viommu;
	struct iommu_pasid_table_cfg cfg = {
		/*
		 * viommu->dev is a virtio device, its parent is the MMIO one
		 * that does DMA.
		 */
		.iommu_dev	= viommu->dev->parent,
		.order		= vdev->pasid_bits,
		.sync		= &viommu_pasid_sync_ops,
	};

	if (!viommu->has_table)
		return 0;

	if (!desc)
		return -ENODEV;

	/* Prepare PASID tables configuration */
	switch (le16_to_cpu(desc->format)) {
	case VIRTIO_IOMMU_PSTF_ARM_SV3:
		fmt = PASID_TABLE_ARM_SMMU_V3;
		ret = viommu_prepare_arm_pst(vdev, &cfg);
		break;
	default:
		dev_err(vdev->dev, "unsupported PASID table format 0x%x\n",
			le16_to_cpu(desc->format));
		return 0;
	}

	if (ret)
		return ret;

	if (!vdomain->pasid_ops) {
		/* Allocate PASID tables */
		ops = iommu_alloc_pasid_ops(fmt, &cfg, vdomain);
		if (!ops)
			return -ENOMEM;

		vdomain->pasid_cfg = cfg;
		vdomain->pasid_ops = ops;

		ret = viommu_setup_pgtable(vdev, vdomain);
		if (ret)
			dev_err(vdev->dev, "could not install page tables\n");
	} else {
		/* TODO: otherwise, check for compatibility with vdev. */
		return -ENOSYS;
	}

	/* Add arch-specific configuration */
	switch (fmt) {
	case PASID_TABLE_ARM_SMMU_V3:
		ret = viommu_config_arm_pst(&vdomain->pasid_cfg, (void *)&req);
		break;
	default:
		ret = -EINVAL;
		WARN_ON(1);
	}
	if (ret)
		goto err_free_ops;

	vdev_for_each_id(i, eid, vdev) {
		req.endpoint = cpu_to_le32(eid);
		ret = viommu_send_req_sync(viommu, &req, sizeof(req));
		if (ret)
			goto err_free_ops;
	}

	dev_dbg(vdev->dev, "uses PASID table format 0x%x\n", fmt);

	return 0;

err_free_ops:
	if (ops) {
		viommu_teardown_pgtable(vdomain);
		iommu_free_pasid_ops(ops);
		vdomain->pasid_ops = NULL;
	}

	return ret;
}

static int viommu_detach_dev(struct viommu_endpoint *vdev)
{
	int ret, i, eid;
	struct virtio_iommu_req_detach req = {
		.head.type	= VIRTIO_IOMMU_T_DETACH,
	};

	vdev_for_each_id(i, eid, vdev) {
		req.endpoint = cpu_to_le32(eid);
		ret = viommu_send_req_sync(vdev->viommu, &req, sizeof(req));
		if (ret)
			return ret;
	}

	return 0;
}

static int viommu_simple_attach(struct viommu_domain *vdomain,
				struct viommu_endpoint *vdev)
{
	int i, eid, ret;
	struct virtio_iommu_req_attach req = {
		.head.type	= VIRTIO_IOMMU_T_ATTACH,
		.domain		= cpu_to_le32(vdomain->id),
	};

	if (!vdomain->viommu->has_map)
		return -ENODEV;

	vdev_for_each_id(i, eid, vdev) {
		req.endpoint = cpu_to_le32(eid);

		ret = viommu_send_req_sync(vdomain->viommu, &req, sizeof(req));
		if (ret)
			return ret;
	}

	if (!vdomain->nr_endpoints) {
		/*
		 * This endpoint is the first to be attached to the domain.
		 * Replay existing mappings if any (e.g. SW MSI).
		 */
		ret = viommu_replay_mappings(vdomain);
	}

	return ret;
}

static int viommu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	int ret = 0;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct viommu_endpoint *vdev = fwspec->iommu_priv;
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	mutex_lock(&vdomain->mutex);
	if (!vdomain->viommu) {
		/*
		 * Initialize the domain proper now that we know which viommu
		 * owns it.
		 */
		ret = viommu_domain_finalise(vdev, domain);
	} else if (vdomain->viommu != vdev->viommu) {
		dev_err(dev, "cannot attach to foreign vIOMMU\n");
		ret = -EXDEV;
	}

#ifdef CONFIG_X86
	if (!ret)
		ret = viommu_dma_init_domain(domain, dev);
#endif
	mutex_unlock(&vdomain->mutex);

	if (ret)
		return ret;

	/*
	 * In the virtio-iommu device, when attaching the endpoint to a new
	 * domain, it is detached from the old one and, if as as a result the
	 * old domain isn't attached to any endpoint, all mappings are removed
	 * from the old domain and it is freed.
	 *
	 * In the driver the old domain still exists, and its mappings will be
	 * recreated if it gets reattached to an endpoint. Otherwise it will be
	 * freed explicitly.
	 *
	 * vdev->vdomain is protected by group->mutex
	 */
	if (vdev->vdomain) {
		vdev->vdomain->nr_endpoints--;
		dev_info(dev, "detached from vdomain %d\n", vdev->vdomain->id);
	}

	ret = viommu_bind_pasid_table(vdev, vdomain);
	if (ret) {
		/*
		 * No PASID support, too bad. Perhaps we can bind a single set
		 * of page tables?
		 */
		ret = viommu_setup_pgtable(vdev, vdomain);
		if (ret)
			dev_err(vdev->dev, "could not install tables\n");
	}

	/* For a PAGING domain, we need either pgtable_ops or the mapping tree. */
	if (!vdomain->pgtable_ops) {
		ret = viommu_simple_attach(vdomain, vdev);
		if (ret)
			return ret;
	} else {
		struct iommu_resv_region *entry;
		list_for_each_entry(entry, &vdev->identity_regions, list) {
			/*
			 * Unfortunately we can't use the default IOMMU direct
			 * stuff, because it's called before attach when there
			 * are no page tables. FIXME: could this be fixed in the
			 * core? It will be broken for other drivers as well.
			 */
			ret = iommu_map(domain, entry->start, entry->start,
					entry->length, entry->prot);
			if (ret)
				return ret;
		}
	}

	vdomain->nr_endpoints++;
	vdev->vdomain = vdomain;

	dev_info(dev, "attached to vdomain %d, viommu %s\n", vdomain->id,
		 dev_name(vdomain->viommu->dev));

	return 0;
}

static int viommu_map(struct iommu_domain *domain, unsigned long iova,
		      phys_addr_t paddr, size_t size, int prot)
{
	int ret;
	int flags;
	struct viommu_mapping *mapping;
	struct virtio_iommu_req_map map;
	struct viommu_domain *vdomain = to_viommu_domain(domain);
	struct io_pgtable_ops *ops = vdomain->pgtable_ops;

	if (ops)
		return ops->map(ops, iova, paddr, size, prot);

	flags = (prot & IOMMU_READ ? VIRTIO_IOMMU_MAP_F_READ : 0) |
		(prot & IOMMU_WRITE ? VIRTIO_IOMMU_MAP_F_WRITE : 0) |
		(prot & IOMMU_MMIO ? VIRTIO_IOMMU_MAP_F_MMIO : 0);

	mapping = viommu_add_mapping(vdomain, iova, paddr, size, flags);
	if (!mapping)
		return -ENOMEM;

	map = (struct virtio_iommu_req_map) {
		.head.type	= VIRTIO_IOMMU_T_MAP,
		.domain		= cpu_to_le32(vdomain->id),
		.virt_start	= cpu_to_le64(iova),
		.phys_start	= cpu_to_le64(paddr),
		.virt_end	= cpu_to_le64(iova + size - 1),
		.flags		= cpu_to_le32(flags),
	};

	if (!vdomain->nr_endpoints)
		return 0;

	ret = viommu_send_req_sync(vdomain->viommu, &map, sizeof(map));
	if (ret)
		viommu_del_mappings(vdomain, iova, size);

	trace_viommu_map(vdomain->viommu->dev, vdomain->id, iova,
			 iova + size - 1, paddr, prot);
	return ret;
}

static size_t viommu_unmap(struct iommu_domain *domain, unsigned long iova,
			   size_t size)
{
	int ret = 0;
	size_t unmapped;
	struct virtio_iommu_req_unmap unmap;
	struct viommu_domain *vdomain = to_viommu_domain(domain);
	struct io_pgtable_ops *ops = vdomain->pgtable_ops;

	if (ops)
		return ops->unmap(ops, iova, size);

	unmapped = viommu_del_mappings(vdomain, iova, size);
	if (unmapped < size)
		return 0;

	/* Device already removed all mappings after detach. */
	if (!vdomain->nr_endpoints)
		return unmapped;

	unmap = (struct virtio_iommu_req_unmap) {
		.head.type	= VIRTIO_IOMMU_T_UNMAP,
		.domain		= cpu_to_le32(vdomain->id),
		.virt_start	= cpu_to_le64(iova),
		.virt_end	= cpu_to_le64(iova + unmapped - 1),
	};

	ret = viommu_add_req(vdomain->viommu, &unmap, sizeof(unmap));
	trace_viommu_unmap(vdomain->viommu->dev, vdomain->id, iova, size);
	return ret ? 0 : unmapped;
}

static phys_addr_t viommu_iova_to_phys(struct iommu_domain *domain,
				       dma_addr_t iova)
{
	u64 paddr = 0;
	unsigned long flags;
	struct viommu_mapping *mapping;
	struct interval_tree_node *node;
	struct viommu_domain *vdomain = to_viommu_domain(domain);
	struct io_pgtable_ops *ops = vdomain->pgtable_ops;

	if (ops)
		return ops->iova_to_phys(ops, iova);

	spin_lock_irqsave(&vdomain->mappings_lock, flags);
	node = interval_tree_iter_first(&vdomain->mappings, iova, iova);
	if (node) {
		mapping = container_of(node, struct viommu_mapping, iova);
		paddr = mapping->paddr + (iova - mapping->iova.start);
	}
	spin_unlock_irqrestore(&vdomain->mappings_lock, flags);

	return paddr;
}

static void viommu_iotlb_sync(struct iommu_domain *domain)
{
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	viommu_sync_req(vdomain->viommu);
}

static void viommu_get_resv_regions(struct device *dev, struct list_head *head)
{
	struct iommu_resv_region *entry, *new_entry, *msi = NULL;
	struct viommu_endpoint *vdev = dev->iommu_fwspec->iommu_priv;
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;

	list_for_each_entry(entry, &vdev->resv_regions, list) {
		/*
		 * If the device registered a bypass MSI windows, use it.
		 * Otherwise add a software-mapped region
		 */
		if (entry->type == IOMMU_RESV_MSI)
			msi = entry;

		new_entry = kmemdup(entry, sizeof(*entry), GFP_KERNEL);
		if (!new_entry)
			return;
		list_add_tail(&new_entry->list, head);
	}

	if (!msi) {
		msi = iommu_alloc_resv_region(MSI_IOVA_BASE, MSI_IOVA_LENGTH,
					      prot, IOMMU_RESV_SW_MSI);
		if (!msi)
			return;

		list_add_tail(&msi->list, head);
	}

	iommu_dma_get_resv_regions(dev, head);
}

static void viommu_put_resv_regions(struct device *dev, struct list_head *head)
{
	struct iommu_resv_region *entry, *next;

	list_for_each_entry_safe(entry, next, head, list)
		kfree(entry);
}

static struct iommu_ops viommu_ops;
static struct virtio_driver virtio_iommu_drv;

static int viommu_match_node(struct device *dev, void *data)
{
	return dev->parent->fwnode == data;
}

static struct viommu_dev *viommu_get_by_fwnode(struct fwnode_handle *fwnode)
{
	struct device *dev = driver_find_device(&virtio_iommu_drv.driver, NULL,
						fwnode, viommu_match_node);
	put_device(dev);

	return dev ? dev_to_virtio(dev)->priv : NULL;
}

static int viommu_add_device(struct device *dev)
{
	int ret;
	struct iommu_group *group;
	struct viommu_endpoint *vdev;
	struct viommu_dev *viommu = NULL;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;

	if (!fwspec || fwspec->ops != &viommu_ops)
		return -ENODEV;

	viommu = viommu_get_by_fwnode(fwspec->iommu_fwnode);
	if (!viommu)
		return -ENODEV;

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev)
		return -ENOMEM;

	vdev->dev = dev;
	vdev->viommu = viommu;
	INIT_LIST_HEAD(&vdev->resv_regions);
	INIT_LIST_HEAD(&vdev->identity_regions);
	fwspec->iommu_priv = vdev;

	vdev->link = device_link_add(dev, viommu->dev, 0);
	if (!vdev->link)
		return -ENODEV;

	if (viommu->probe_size) {
		/* Get additional information for this endpoint */
		ret = viommu_probe_endpoint(viommu, dev);
		if (ret)
			return ret;
	}

	ret = iommu_device_link(&viommu->iommu, dev);
	if (ret)
		goto err_free_dev;

	/*
	 * Last step creates a default domain and attaches to it. Everything
	 * must be ready.
	 */
	group = iommu_group_get_for_dev(dev);
	if (IS_ERR(group)) {
		ret = PTR_ERR(group);
		goto err_unlink_dev;
	}

	iommu_group_put(group);

	return PTR_ERR_OR_ZERO(group);

err_unlink_dev:
	iommu_device_unlink(&viommu->iommu, dev);

err_free_dev:
	viommu_put_resv_regions(dev, &vdev->resv_regions);
	viommu_put_resv_regions(dev, &vdev->identity_regions);
	kfree(vdev);

	return ret;
}

static void viommu_remove_device(struct device *dev)
{
	struct viommu_endpoint *vdev;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;

	if (!fwspec || fwspec->ops != &viommu_ops)
		return;

	vdev = fwspec->iommu_priv;

	viommu_detach_dev(vdev);
	iommu_group_remove_device(dev);
	iommu_device_unlink(&vdev->viommu->iommu, dev);
	viommu_put_resv_regions(dev, &vdev->resv_regions);
	viommu_put_resv_regions(dev, &vdev->identity_regions);
	device_link_del(vdev->link);
	kfree(vdev->pstf);
	kfree(vdev->pgtf);
	kfree(vdev);
}

static struct iommu_group *viommu_device_group(struct device *dev)
{
	if (dev_is_pci(dev))
		return pci_device_group(dev);
	else
		return generic_device_group(dev);
}

static int viommu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	return iommu_fwspec_add_ids(dev, args->args, 1);
}

static struct iommu_ops viommu_ops = {
	.domain_alloc		= viommu_domain_alloc,
	.domain_free		= viommu_domain_free,
	.attach_dev		= viommu_attach_dev,
	.map			= viommu_map,
	.unmap			= viommu_unmap,
	.map_sg			= default_iommu_map_sg,
	.iova_to_phys		= viommu_iova_to_phys,
	.iotlb_sync		= viommu_iotlb_sync,
	.add_device		= viommu_add_device,
	.remove_device		= viommu_remove_device,
	.device_group		= viommu_device_group,
	.get_resv_regions	= viommu_get_resv_regions,
	.put_resv_regions	= viommu_put_resv_regions,
	.of_xlate		= viommu_of_xlate,
};

static int viommu_init_vqs(struct viommu_dev *viommu)
{
	struct virtio_device *vdev = dev_to_virtio(viommu->dev);
	const char *names[] = { "request", "event" };
	vq_callback_t *callbacks[] = {
		NULL, /* No async requests */
		viommu_event_handler,
	};

	return virtio_find_vqs(vdev, VIOMMU_NR_VQS, viommu->vqs, callbacks,
			       names, NULL);
}

static int viommu_fill_evtq(struct viommu_dev *viommu)
{
	int i, ret;
	struct scatterlist sg[1];
	struct viommu_event *evts;
	struct virtqueue *vq = viommu->vqs[VIOMMU_EVENT_VQ];
	size_t nr_evts = vq->num_free;

	viommu->evts = evts = devm_kmalloc_array(viommu->dev, nr_evts,
						 sizeof(*evts), GFP_KERNEL);
	if (!evts)
		return -ENOMEM;

	for (i = 0; i < nr_evts; i++) {
		sg_init_one(sg, &evts[i], sizeof(*evts));
		ret = virtqueue_add_inbuf(vq, sg, 1, &evts[i], GFP_KERNEL);
		if (ret)
			return ret;
	}

	return 0;
}

#ifdef CONFIG_X86
static dma_addr_t viommu_dma_map_page(struct device *dev, struct page *page,
				      unsigned long offset, size_t size,
				      enum dma_data_direction dir,
				      unsigned long attrs)
{
	return iommu_dma_map_page(dev, page, offset, size,
				  dma_info_to_prot(dir, 0, attrs));
}

static int viommu_dma_map_sg(struct device *dev, struct scatterlist *sglist, int nelems,
			     enum dma_data_direction dir, unsigned long attrs)
{
	return iommu_dma_map_sg(dev, sglist, nelems,
				dma_info_to_prot(dir, 0, attrs));
}

static void __flush_page(struct device *dev, const void *virt, phys_addr_t phys)
{
}

/* Referring to __iommu_alloc_attrs, simplified version */
static void *viommu_dma_map_alloc_coherent(struct device *dev, size_t size,
					   dma_addr_t *handle, gfp_t gfp,
					   unsigned long attrs)
{
	bool coherent = true;
	int ioprot = dma_info_to_prot(DMA_BIDIRECTIONAL, coherent, attrs);
	pgprot_t prot = PAGE_KERNEL;
	size_t iosize = size;
	struct page **pages;
	void *addr;

	if (WARN(!dev, "cannot create IOMMU mapping for unknown device\n"))
		return NULL;

	size = PAGE_ALIGN(size);

	if (WARN(attrs & DMA_ATTR_FORCE_CONTIGUOUS, "CONTIGUOUS unsupported") ||
	    WARN(!gfpflags_allow_blocking(gfp), "atomic alloc unsupported"))
		return NULL;

	/*
	 * Some drivers rely on this, and we probably don't want the
	 * possibility of stale kernel data being read by devices anyway.
	 */
	gfp |= __GFP_ZERO;

	pages = iommu_dma_alloc(dev, iosize, gfp, attrs, ioprot,
				handle, __flush_page);
	if (!pages)
		return NULL;

	addr = dma_common_pages_remap(pages, size, VM_USERMAP, prot,
				      __builtin_return_address(0));
	if (!addr)
		iommu_dma_free(dev, pages, iosize, handle);

	return addr;
}

/* From __iommu_free_attrs */
static void viommu_dma_map_free(struct device *dev, size_t size, void *cpu_addr,
				dma_addr_t handle, unsigned long attrs)
{
	size_t iosize = size;
	struct vm_struct *area;

	size = PAGE_ALIGN(size);
	if (WARN_ON(!is_vmalloc_addr(cpu_addr)))
	    return;

	area = find_vm_area(cpu_addr);
	if (WARN_ON(!area || !area->pages))
		return;

	iommu_dma_free(dev, area->pages, iosize, &handle);
	dma_common_free_remap(cpu_addr, size, VM_USERMAP);
}

static struct dma_map_ops viommu_dma_ops = {
	.alloc			= viommu_dma_map_alloc_coherent,
	.free			= viommu_dma_map_free,
	.map_sg			= viommu_dma_map_sg,
	.unmap_sg		= iommu_dma_unmap_sg,
	.map_page		= viommu_dma_map_page,
	.unmap_page		= iommu_dma_unmap_page,
	.map_resource		= iommu_dma_map_resource,
	.unmap_resource		= iommu_dma_unmap_resource,
	.mapping_error		= iommu_dma_mapping_error,
};
#endif

static int viommu_probe(struct virtio_device *vdev)
{
	struct device *parent_dev = vdev->dev.parent;
	struct viommu_dev *viommu = NULL;
	struct device *dev = &vdev->dev;
	u64 input_start = 0;
	u64 input_end = -1UL;
	int ret;

	viommu = devm_kzalloc(dev, sizeof(*viommu), GFP_KERNEL);
	if (!viommu)
		return -ENOMEM;

	spin_lock_init(&viommu->request_lock);
	ida_init(&viommu->domain_ids);
	viommu->dev = dev;
	viommu->vdev = vdev;
	INIT_LIST_HEAD(&viommu->requests);

	ret = viommu_init_vqs(viommu);
	if (ret)
		return ret;

	virtio_cread(vdev, struct virtio_iommu_config, page_size_mask,
		     &viommu->pgsize_bitmap);

	if (!viommu->pgsize_bitmap) {
		ret = -EINVAL;
		goto err_free_vqs;
	}

	viommu->domain_bits = 32;

	/* Optional features */
	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_INPUT_RANGE,
			     struct virtio_iommu_config, input_range.start,
			     &input_start);

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_INPUT_RANGE,
			     struct virtio_iommu_config, input_range.end,
			     &input_end);

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_DOMAIN_BITS,
			     struct virtio_iommu_config, domain_bits,
			     &viommu->domain_bits);

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_PROBE,
			     struct virtio_iommu_config, probe_size,
			     &viommu->probe_size);

	viommu->has_table = virtio_has_feature(vdev, VIRTIO_IOMMU_F_ATTACH_TABLE);
	viommu->has_map = virtio_has_feature(vdev, VIRTIO_IOMMU_F_MAP_UNMAP);
	if (!viommu->has_table && !viommu->has_map) {
		ret = -EINVAL;
		goto err_free_vqs;
	}

	viommu->geometry = (struct iommu_domain_geometry) {
		.aperture_start	= input_start,
		.aperture_end	= input_end,
		.force_aperture	= true,
	};

	viommu_ops.pgsize_bitmap = viommu->pgsize_bitmap;

	virtio_device_ready(vdev);

	/* Populate the event queue with buffers */
	ret = viommu_fill_evtq(viommu);
	if (ret)
		goto err_free_vqs;

	ret = iommu_device_sysfs_add(&viommu->iommu, dev, NULL, "%s",
				     virtio_bus_name(vdev));
	if (ret)
		goto err_free_vqs;

	iommu_device_set_ops(&viommu->iommu, &viommu_ops);
	iommu_device_set_fwnode(&viommu->iommu, parent_dev->fwnode);

	iommu_device_register(&viommu->iommu);

	/* Hack: this should be an arch initcall */
#ifdef CONFIG_X86
	{
		static bool __inited = false;

		if (!__inited) {
			dma_ops = &viommu_dma_ops;
			iommu_dma_init();
			__inited = true;
		}
	}
#endif

#ifdef CONFIG_PCI
	if (pci_bus_type.iommu_ops != &viommu_ops) {
		pci_request_acs();
		ret = bus_set_iommu(&pci_bus_type, &viommu_ops);
		if (ret)
			goto err_unregister;
	}
#endif
#ifdef CONFIG_ARM_AMBA
	if (amba_bustype.iommu_ops != &viommu_ops) {
		ret = bus_set_iommu(&amba_bustype, &viommu_ops);
		if (ret)
			goto err_unregister;
	}
#endif
	if (platform_bus_type.iommu_ops != &viommu_ops) {
		ret = bus_set_iommu(&platform_bus_type, &viommu_ops);
		if (ret)
			goto err_unregister;
	}

	vdev->priv = viommu;

	dev_info(dev, "input address: %u bits\n",
		 order_base_2(viommu->geometry.aperture_end));
	dev_info(dev, "page mask: %#llx\n", viommu->pgsize_bitmap);

	return 0;

err_unregister:
	iommu_device_sysfs_remove(&viommu->iommu);
	iommu_device_unregister(&viommu->iommu);
err_free_vqs:
	vdev->config->del_vqs(vdev);

	return ret;
}

static void viommu_remove(struct virtio_device *vdev)
{
	struct viommu_dev *viommu = vdev->priv;

	iommu_device_sysfs_remove(&viommu->iommu);
	iommu_device_unregister(&viommu->iommu);

	/* Stop all virtqueues */
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	dev_info(&vdev->dev, "device removed\n");
}

static void viommu_config_changed(struct virtio_device *vdev)
{
	dev_warn(&vdev->dev, "config changed\n");
}

static unsigned int features[] = {
	VIRTIO_IOMMU_F_MAP_UNMAP,
	VIRTIO_IOMMU_F_DOMAIN_BITS,
	VIRTIO_IOMMU_F_INPUT_RANGE,
	VIRTIO_IOMMU_F_PROBE,
	VIRTIO_IOMMU_F_ATTACH_TABLE,
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_IOMMU, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_iommu_drv = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.probe			= viommu_probe,
	.remove			= viommu_remove,
	.config_changed		= viommu_config_changed,
};

module_virtio_driver(virtio_iommu_drv);

MODULE_DESCRIPTION("Virtio IOMMU driver");
MODULE_AUTHOR("Jean-Philippe Brucker <jean-philippe.brucker@arm.com>");
MODULE_LICENSE("GPL v2");
