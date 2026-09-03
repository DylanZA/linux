/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_DATAFS_H
#define _UAPI_LINUX_DATAFS_H

#include <linux/types.h>

#define DATAFS_URING_CMD_RECV_DEVMEM	1
#define DATAFS_URING_CMD_COPY_RESPONSE	2

enum datafs_uring_cmd_flags {
	DATAFS_URING_F_WAIT_SOCKET	= 1U << 0,
	DATAFS_URING_F_DEVMEM_DONTNEED	= 1U << 1,
};

#define DATAFS_DEVMEM_CQE_LOAN_SHIFT	16
#define DATAFS_DEVMEM_CQE_LOAN_MASK	0xffffU
#define DATAFS_DEVMEM_CQE_F_COPY_REQUEST	(1U << 14)

/*
 * Command payload for DATAFS_URING_CMD_RECV_DEVMEM, stored in sqe->cmd.
 * sqe->len is the read length or token count, sqe->buf_group is the host
 * buffer group or socket-loan ID, and the storage named sqe->zcrx_ifq_idx by
 * io_uring carries the netdev RX dma-buf binding ID.
 *
 * Data completions are CQE32 entries with IORING_CQE_F_MORE.  res contains
 * frag_size and the extension below contains the remaining dmabuf_cmsg
 * fields.  For dma-buf extents, the socket-loan ID that owns frag_token is
 * encoded in cqe->flags at DATAFS_DEVMEM_CQE_LOAN_SHIFT.  Linear fallback
 * uses an io_uring provided buffer, sets IORING_CQE_F_BUFFER, and reports a
 * zero dmabuf_id.  The terminal CQE has no MORE bit and reports total bytes or
 * an error.
 *
 * DATAFS_URING_F_DEVMEM_DONTNEED returns tokens after userspace has finished
 * with dma-buf extents.  WAIT_SOCKET is invalid in this mode.  Fields unused
 * by the selected operation must be zero.
 */
struct datafs_uring_devmem_cmd {
	__u64 offset;
	__u32 flags;
	__u32 reserved;
};

struct datafs_uring_devmem_cqe {
	__u64 frag_offset;
	__u32 frag_token;
	__u32 dmabuf_id;
};

/*
 * A COPY_REQUEST CQE asks userspace to make a device-memory range CPU
 * accessible.  res is the requested size, key identifies the request, and
 * frag_offset is the source offset in the RX dma-buf selected by the original
 * receive command.  The dma-buf token remains owned by datafs until the
 * response is consumed.
 */
struct datafs_uring_copy_cqe {
	__u64 key;
	__u64 frag_offset;
};

/*
 * Command payload for DATAFS_URING_CMD_COPY_RESPONSE, stored in sqe->cmd.
 * sqe->addr and sqe->len select bytes in the registered buffer named by
 * sqe->buf_index.  They must exactly match the COPY_REQUEST size.
 */
struct datafs_uring_copy_cmd {
	__u64 key;
	__u64 reserved;
};

#endif /* _UAPI_LINUX_DATAFS_H */
