/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Virtio-iommu definition v0.9-devel
 *
 * Copyright (C) 2018 Arm Ltd.
 */
#ifndef _UAPI_LINUX_VIRTIO_IOMMU_H
#define _UAPI_LINUX_VIRTIO_IOMMU_H

#include <linux/types.h>

/* Feature bits */
#define VIRTIO_IOMMU_F_INPUT_RANGE		0
#define VIRTIO_IOMMU_F_DOMAIN_BITS		1
#define VIRTIO_IOMMU_F_MAP_UNMAP		2
#define VIRTIO_IOMMU_F_BYPASS			3
#define VIRTIO_IOMMU_F_PROBE			4
#define VIRTIO_IOMMU_F_ATTACH_TABLE		5

struct virtio_iommu_config {
	/* Supported page sizes */
	__u64					page_size_mask;
	/* Supported IOVA range */
	struct virtio_iommu_range {
		__u64				start;
		__u64				end;
	} input_range;
	/* Max domain ID size */
	__u8					domain_bits;
	__u8					padding[3];
	/* Probe buffer size */
	__u32					probe_size;
};

/* Request types */
#define VIRTIO_IOMMU_T_ATTACH			0x01
#define VIRTIO_IOMMU_T_DETACH			0x02
#define VIRTIO_IOMMU_T_MAP			0x03
#define VIRTIO_IOMMU_T_UNMAP			0x04
#define VIRTIO_IOMMU_T_PROBE			0x05
#define VIRTIO_IOMMU_T_ATTACH_TABLE		0x06
#define VIRTIO_IOMMU_T_INVALIDATE		0x07

/* Status types */
#define VIRTIO_IOMMU_S_OK			0x00
#define VIRTIO_IOMMU_S_IOERR			0x01
#define VIRTIO_IOMMU_S_UNSUPP			0x02
#define VIRTIO_IOMMU_S_DEVERR			0x03
#define VIRTIO_IOMMU_S_INVAL			0x04
#define VIRTIO_IOMMU_S_RANGE			0x05
#define VIRTIO_IOMMU_S_NOENT			0x06
#define VIRTIO_IOMMU_S_FAULT			0x07

struct virtio_iommu_req_head {
	__u8					type;
	__u8					reserved[3];
};

struct virtio_iommu_req_tail {
	__u8					status;
	__u8					reserved[3];
};

struct virtio_iommu_req_attach {
	struct virtio_iommu_req_head		head;
	__le32					domain;
	__le32					endpoint;
	__u8					reserved[8];
	struct virtio_iommu_req_tail		tail;
};

struct virtio_iommu_req_detach {
	struct virtio_iommu_req_head		head;
	__le32					endpoint;
	__u8					reserved[4];
	struct virtio_iommu_req_tail		tail;
};

struct virtio_iommu_req_attach_table {
	struct virtio_iommu_req_head		head;
	__le32					domain;
	__le32					endpoint;
	__le16					format;
	__u8					reserved[62];
	struct virtio_iommu_req_tail		tail;
};

/* Arm SMMUv3 PASID Table Descriptor */
struct virtio_iommu_req_attach_pst_arm {
	struct virtio_iommu_req_head		head;
	__le32					domain;
	__le32					endpoint;
	__le16					format;
#define VIRTIO_IOMMU_PSTF_ARM_SV3_LINEAR	0x0
#define VIRTIO_IOMMU_PSTF_ARM_SV3_4KL2		0x1
#define VIRTIO_IOMMU_PSTF_ARM_SV3_64KL2		0x2
	__u8					s1fmt;
#define VIRTIO_IOMMU_PSTF_ARM_SV3_DSS_TERM	0x0
#define VIRTIO_IOMMU_PSTF_ARM_SV3_DSS_BYPASS	0x1
#define VIRTIO_IOMMU_PSTF_ARM_SV3_DSS_0		0x2
	__u8					s1dss;
	__le64					s1contextptr;
	__le32					s1cdmax;
	__u8					reserved[48];
	struct virtio_iommu_req_tail		tail;
};

/* Arm LPAE Page Table Descriptor */
struct virtio_iommu_req_attach_pgt_arm {
	struct virtio_iommu_req_head		head;
	__le32					domain;
	__le32					endpoint;
	__le16					format;
	__le16					asid;
	/* TCR_EL1 fields, in the ARMv8 Architecture Reference Manual (DDI0487B) */
#define VIRTIO_IOMMU_PGTF_ARM_NFD1		(1ULL << 54)
#define VIRTIO_IOMMU_PGTF_ARM_NFD0		(1ULL << 53)
#define VIRTIO_IOMMU_PGTF_ARM_HWU162		(1ULL << 50)
#define VIRTIO_IOMMU_PGTF_ARM_HWU161		(1ULL << 49)
#define VIRTIO_IOMMU_PGTF_ARM_HWU160		(1ULL << 48)
#define VIRTIO_IOMMU_PGTF_ARM_HWU159		(1ULL << 47)
#define VIRTIO_IOMMU_PGTF_ARM_HWU062		(1ULL << 46)
#define VIRTIO_IOMMU_PGTF_ARM_HWU061		(1ULL << 45)
#define VIRTIO_IOMMU_PGTF_ARM_HWU060		(1ULL << 44)
#define VIRTIO_IOMMU_PGTF_ARM_HWU059		(1ULL << 43)
#define VIRTIO_IOMMU_PGTF_ARM_HPD1		(1ULL << 42)
#define VIRTIO_IOMMU_PGTF_ARM_HPD0		(1ULL << 41)
#define VIRTIO_IOMMU_PGTF_ARM_HD		(1ULL << 40)
#define VIRTIO_IOMMU_PGTF_ARM_HA		(1ULL << 39)
#define VIRTIO_IOMMU_PGTF_ARM_TBI1		(1ULL << 38)
#define VIRTIO_IOMMU_PGTF_ARM_TBI0		(1ULL << 37)
#define VIRTIO_IOMMU_PGTF_ARM_AS		(1ULL << 36)
#define VIRTIO_IOMMU_PGTF_ARM_IPS_SHIFT		32
#define VIRTIO_IOMMU_PGTF_ARM_IPS_MASK		0x7ULL
#define VIRTIO_IOMMU_PGTF_ARM_TG1_SHIFT		30
#define VIRTIO_IOMMU_PGTF_ARM_TG1_MASK		0x3
#define VIRTIO_IOMMU_PGTF_ARM_SH1_SHIFT		28
#define VIRTIO_IOMMU_PGTF_ARM_SH1_MASK		0x3
#define VIRTIO_IOMMU_PGTF_ARM_ORGN1_SHIFT	26
#define VIRTIO_IOMMU_PGTF_ARM_ORGN1_MASK	0x3
#define VIRTIO_IOMMU_PGTF_ARM_IRGN1_SHIFT	24
#define VIRTIO_IOMMU_PGTF_ARM_IRGN1_MASK	0x3
#define VIRTIO_IOMMU_PGTF_ARM_EPD1		(1 << 23)
#define VIRTIO_IOMMU_PGTF_ARM_A1		(1 << 22)
#define VIRTIO_IOMMU_PGTF_ARM_T1SZ_SHIFT	16
#define VIRTIO_IOMMU_PGTF_ARM_T1SZ_MASK		0x3f
#define VIRTIO_IOMMU_PGTF_ARM_TG0_SHIFT		14
#define VIRTIO_IOMMU_PGTF_ARM_TG0_MASK		0x3
#define VIRTIO_IOMMU_PGTF_ARM_SH0_SHIFT		12
#define VIRTIO_IOMMU_PGTF_ARM_SH0_MASK		0x3
#define VIRTIO_IOMMU_PGTF_ARM_ORGN0_SHIFT	10
#define VIRTIO_IOMMU_PGTF_ARM_ORGN0_MASK	0x3
#define VIRTIO_IOMMU_PGTF_ARM_IRGN0_SHIFT	8
#define VIRTIO_IOMMU_PGTF_ARM_IRGN0_MASK	0x3
#define VIRTIO_IOMMU_PGTF_ARM_EPD0		(1 << 7)
#define VIRTIO_IOMMU_PGTF_ARM_T0SZ_SHIFT	0
#define VIRTIO_IOMMU_PGTF_ARM_T0SZ_MASK		0x3f
	__le64					tcr;
	__le64					ttbr0;
	__le64					ttbr1;
	__le64					mair;
	__u8					reserved[28];
	struct virtio_iommu_req_tail		tail;
};

#define VIRTIO_IOMMU_MAP_F_READ			(1 << 0)
#define VIRTIO_IOMMU_MAP_F_WRITE		(1 << 1)
#define VIRTIO_IOMMU_MAP_F_EXEC			(1 << 2)
#define VIRTIO_IOMMU_MAP_F_MMIO			(1 << 3)

#define VIRTIO_IOMMU_MAP_F_MASK			(VIRTIO_IOMMU_MAP_F_READ |	\
						 VIRTIO_IOMMU_MAP_F_WRITE |	\
						 VIRTIO_IOMMU_MAP_F_EXEC |	\
						 VIRTIO_IOMMU_MAP_F_MMIO)

struct virtio_iommu_req_map {
	struct virtio_iommu_req_head		head;
	__le32					domain;
	__le64					virt_start;
	__le64					virt_end;
	__le64					phys_start;
	__le32					flags;
	struct virtio_iommu_req_tail		tail;
};

struct virtio_iommu_req_unmap {
	struct virtio_iommu_req_head		head;
	__le32					domain;
	__le64					virt_start;
	__le64					virt_end;
	__u8					reserved[4];
	struct virtio_iommu_req_tail		tail;
};

#define VIRTIO_IOMMU_PROBE_T_NONE		0
#define VIRTIO_IOMMU_PROBE_T_RESV_MEM		1
#define VIRTIO_IOMMU_PROBE_T_PAGE_SIZE_MASK	2
#define VIRTIO_IOMMU_PROBE_T_INPUT_RANGE	3
#define VIRTIO_IOMMU_PROBE_T_OUTPUT_SIZE	4
#define VIRTIO_IOMMU_PROBE_T_PASID_SIZE		5
#define VIRTIO_IOMMU_PROBE_T_PAGE_TABLE_FMT	6
#define VIRTIO_IOMMU_PROBE_T_PASID_TABLE_FMT	7

#define VIRTIO_IOMMU_PROBE_T_MASK		0xfff

struct virtio_iommu_probe_property {
	__le16					type;
	__le16					length;
};

#define VIRTIO_IOMMU_RESV_MEM_T_RESERVED	0
#define VIRTIO_IOMMU_RESV_MEM_T_MSI		1
#define VIRTIO_IOMMU_RESV_MEM_T_IDENTITY	2

struct virtio_iommu_probe_resv_mem {
	struct virtio_iommu_probe_property	head;
	__u8					subtype;
	__u8					reserved[3];
	__le64					start;
	__le64					end;
	__le32					flags;
	__le32					padding;
};

struct virtio_iommu_probe_page_size_mask {
	struct virtio_iommu_probe_property	head;
	__u8					reserved[4];
	__le64					mask;
};

struct virtio_iommu_probe_input_range {
	struct virtio_iommu_probe_property	head;
	__u8					reserved[4];
	__le64					start;
	__le64					end;
};

struct virtio_iommu_probe_output_size {
	struct virtio_iommu_probe_property	head;
	__u8					bits;
	__u8					reserved[3];
};

struct virtio_iommu_probe_pasid_size {
	struct virtio_iommu_probe_property	head;
	__u8					bits;
	__u8					reserved[3];
};

struct virtio_iommu_probe_table_format {
	struct virtio_iommu_probe_property	head;
#define VIRTIO_IOMMU_PGTF_ARM_LPAE		1
#define VIRTIO_IOMMU_PSTF_ARM_SV3		2
	__le16					format;
	__u8					reserved[2];
};

/* Arm LPAE Page Table Format */
struct virtio_iommu_probe_pgtf_arm {
	struct virtio_iommu_probe_property	head;
	__le16					format;
	__u8					asid_bits;
	__u8					reserved[1];

#define VIRTIO_IOMMU_PGTF_ARM_LPAE_F_HW_ACCESS	(1ULL << 0)
#define VIRTIO_IOMMU_PGTF_ARM_LPAE_F_HW_DIRTY	(1ULL << 1)
#define VIRTIO_IOMMU_PGTF_ARM_LPAE_F_HW_FLOAT	(1ULL << 2)
#define VIRTIO_IOMMU_PGTF_ARM_LPAE_F_HPD	(1ULL << 3)
	__le64					flags;
};

/* Arm SMMUv3 PASID Table Format */
struct virtio_iommu_probe_pstf_arm {
	struct virtio_iommu_probe_property	head;
	__le16					format;
	__u8					reserved[2];

	/* Info needed for populating the table */
#define VIRTIO_IOMMU_PSTF_ARM_SV3_F_STALL	(1ULL << 0)
#define VIRTIO_IOMMU_PSTF_ARM_SV3_F_STALL_FORCE	(1ULL << 1)
#define VIRTIO_IOMMU_PSTF_ARM_SV3_F_BTM		(1ULL << 2)
	__le64					flags;
};

struct virtio_iommu_req_probe {
	struct virtio_iommu_req_head		head;
	__le32					endpoint;
	__u8					reserved[64];

	__u8					properties[];

	/*
	 * Tail follows the variable-length properties array. No padding,
	 * property lengths are all aligned on 8 bytes.
	 */
};

#define VIRTIO_IOMMU_INVAL_S_DOMAIN		(1 << 0)
/* 'pasid', 'id' are valid */
#define VIRTIO_IOMMU_INVAL_S_PASID		(1 << 1)
/* 'pasid', 'id', 'virt_start', 'nr_pages' and 'granule' are valid */
#define VIRTIO_IOMMU_INVAL_S_VA			(1 << 2)

#define VIRTIO_IOMMU_INVAL_F_CONFIG		(1 << 0)
#define VIRTIO_IOMMU_INVAL_F_LEAF		(1 << 1)

struct virtio_iommu_req_invalidate {
	struct virtio_iommu_req_head		head;
	__le16					scope;
	__le16					flags;
	__le32					domain;
	__le32					pasid;
	__le64					id;
	__le64					virt_start;
	__le64					nr_pages;
	/* Page size, in nr of bits, typically 12 for 4k, 30 for 2MB, etc.) */
	__u8					granule;
	__u8					reserved[19];
	struct virtio_iommu_req_tail		tail;
};

/* Fault types */
#define VIRTIO_IOMMU_FAULT_R_UNKNOWN		0
#define VIRTIO_IOMMU_FAULT_R_DOMAIN		1
#define VIRTIO_IOMMU_FAULT_R_MAPPING		2

#define VIRTIO_IOMMU_FAULT_F_READ		(1 << 0)
#define VIRTIO_IOMMU_FAULT_F_WRITE		(1 << 1)
#define VIRTIO_IOMMU_FAULT_F_EXEC		(1 << 2)
#define VIRTIO_IOMMU_FAULT_F_ADDRESS		(1 << 8)

struct virtio_iommu_fault {
	__u8					reason;
	__u8					reserved[3];
	__le32					flags;
	__le32					endpoint;
	__le32					pasid;
	__le64					address;
};

#endif
