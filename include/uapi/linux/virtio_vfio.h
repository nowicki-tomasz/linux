/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Virtio VFIO platform device definition
 *
 * Copyright (C) 2020 Semihalf
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

struct virtio_vfio_req_hdr {
	__le32				dev_type;
	__u8				req_type;
	__u8				reserved[3];
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

/* Clocks */

/* Clock request types */
#define VIRTIO_VFIO_REQ_CLK_PREPARE		0x01
#define VIRTIO_VFIO_REQ_CLK_ENABLE		0x02
#define VIRTIO_VFIO_REQ_CLK_UNPREPARE		0x03
#define VIRTIO_VFIO_REQ_CLK_DISABLE		0x04
#define VIRTIO_VFIO_REQ_CLK_SET_RATE		0x05
#define VIRTIO_VFIO_REQ_CLK_RECALC_RATE		0x06
#define VIRTIO_VFIO_REQ_CLK_GET_FLAGS		0x07

struct virtio_vfio_clk_prepare {
	struct virtio_vfio_req_hdr	hdr;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_clk_unprepare {
	struct virtio_vfio_req_hdr	hdr;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_clk_enable {
	struct virtio_vfio_req_hdr	hdr;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_clk_disable {
	struct virtio_vfio_req_hdr	hdr;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_clk_rate {
	struct virtio_vfio_req_hdr	hdr;
	__le64				parent_rate;
	__le64				rate;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_clk_flags {
	struct virtio_vfio_req_hdr	hdr;
	__le64				flags;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_clk_event {
	unsigned long			msg;
	unsigned long			old_rate;
	unsigned long			new_rate;
} __attribute__((packed));

/* Regulators */

/* Clock request types */
#define VIRTIO_VFIO_REQ_REGULATOR_GET_TYPE		0x01
#define VIRTIO_VFIO_REQ_REGULATOR_GET_N_VOLTAGES	0x02
#define VIRTIO_VFIO_REQ_REGULATOR_ENABLE		0x03
#define VIRTIO_VFIO_REQ_REGULATOR_DISABLE		0x04
#define VIRTIO_VFIO_REQ_REGULATOR_IS_ENABLED		0x05
#define VIRTIO_VFIO_REQ_REGULATOR_GET_CUR_LIMIT		0x06
#define VIRTIO_VFIO_REQ_REGULATOR_SET_CUR_LIMIT		0x07
#define VIRTIO_VFIO_REQ_REGULATOR_LIST_VOLTAGE		0x08
#define VIRTIO_VFIO_REQ_REGULATOR_MAP_VOLTAGE		0x09
#define VIRTIO_VFIO_REQ_REGULATOR_GET_VOLTAGE		0x0a
#define VIRTIO_VFIO_REQ_REGULATOR_SET_VOLTAGE		0x0b

struct virtio_vfio_regulator_type {
	struct virtio_vfio_req_hdr	hdr;
	__le64				type;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_n_voltages {
	struct virtio_vfio_req_hdr	hdr;
	__le64				n_voltages;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_enable {
	struct virtio_vfio_req_hdr	hdr;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_disable {
	struct virtio_vfio_req_hdr	hdr;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_is_enable {
	struct virtio_vfio_req_hdr	hdr;
	__le64				is_enabled;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_get_cur_limit {
	struct virtio_vfio_req_hdr	hdr;
	__le64				cur_limit;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_set_cur_limit {
	struct virtio_vfio_req_hdr	hdr;
	__le64				min_uA;
	__le64				max_uA;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_list_voltage {
	struct virtio_vfio_req_hdr	hdr;
	__le64				selector;
	__le64				vol;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_map_voltage {
	struct virtio_vfio_req_hdr	hdr;
	__le64				min_uV;
	__le64				max_uV;
	__le64				selector;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_get_voltage {
	struct virtio_vfio_req_hdr	hdr;
	__le64				vol;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_set_voltage {
	struct virtio_vfio_req_hdr	hdr;
	__le64				min_uV;
	__le64				max_uV;
	__le64				selector;
	struct virtio_vfio_resp_status	resp;
} __attribute__((packed));

struct virtio_vfio_regulator_event {
	unsigned long			msg;
	unsigned long			old_vol;
	unsigned long			new_vol;
} __attribute__((packed));

#endif
