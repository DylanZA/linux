/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_TCPFS_H
#define _UAPI_LINUX_TCPFS_H

#include <linux/types.h>

#define TCPFS_URING_CMD_READ_ZC		1

/*
 * Standard SQE layout for TCPFS_URING_CMD_READ_ZC:
 *
 * sqe->cmd_op		= TCPFS_URING_CMD_READ_ZC
 * sqe->len		= read length
 * sqe->addr3		= file offset
 * sqe->zcrx_ifq_idx	= registered zero-copy receive queue
 *
 * The ring must be created with IORING_SETUP_CQE32.  Data CQEs have
 * IORING_CQE_F_MORE set.  Their res field is the data length and the second
 * CQE is a struct tcpfs_uring_zc_cqe.  The final CQE does not have
 * IORING_CQE_F_MORE set and reports the total byte count or an error.
 */

struct tcpfs_uring_zc_cqe {
	__u64 area_offset;
	__u64 file_offset;
};

#endif /* _UAPI_LINUX_TCPFS_H */
