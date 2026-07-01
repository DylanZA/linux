/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_IO_URING_ZCRX_CMD_H
#define _LINUX_IO_URING_ZCRX_CMD_H

#include <linux/errno.h>
#include <linux/types.h>

struct io_uring_cmd;
struct io_uring_zcrx_ifq;
struct socket;

#if defined(CONFIG_IO_URING_ZCRX)
/**
 * io_uring_cmd_zcrx_get() - Pin a registered ZCRX interface queue.
 * @cmd: uring command whose ring owns the registration
 * @ifq_idx: registration identifier supplied in the SQE
 * @ifq: returns an opaque, reference-counted interface queue
 *
 * The returned reference must be released with io_uring_cmd_zcrx_put().
 *
 * Return: 0 on success or a negative errno.
 */
int io_uring_cmd_zcrx_get(struct io_uring_cmd *cmd, u32 ifq_idx,
			  struct io_uring_zcrx_ifq **ifq);

/**
 * io_uring_cmd_zcrx_put() - Release a registered ZCRX interface queue.
 * @ifq: interface queue returned by io_uring_cmd_zcrx_get()
 */
void io_uring_cmd_zcrx_put(struct io_uring_zcrx_ifq *ifq);

/**
 * io_uring_cmd_zcrx_peek() - Copy queued TCP data without consuming it.
 * @ifq: interface queue that owns any provider-backed fragments
 * @sock: TCP socket to inspect
 * @buf: kernel buffer receiving the copied bytes
 * @len: maximum number of bytes to copy
 *
 * This helper never blocks and supports kernel-readable ZCRX memory only.
 *
 * Return: number of bytes copied or a negative errno.
 */
int io_uring_cmd_zcrx_peek(struct io_uring_zcrx_ifq *ifq,
			   struct socket *sock, void *buf, unsigned int len);

/**
 * io_uring_cmd_zcrx_consume() - Consume queued TCP data without copying it.
 * @sock: TCP socket to consume from
 * @len: maximum number of bytes to consume
 *
 * Return: number of bytes consumed or a negative errno.
 */
int io_uring_cmd_zcrx_consume(struct socket *sock, unsigned int len);

/**
 * io_uring_cmd_zcrx_recv() - Complete queued TCP data from ZCRX buffers.
 * @cmd: uring command receiving auxiliary CQEs
 * @ifq: interface queue that owns the registered buffers
 * @sock: TCP socket to consume from
 * @len: maximum number of bytes to consume
 * @stream_offset: logical offset associated with the first returned byte
 * @issue_flags: io_uring command issue context
 *
 * The helper never blocks. Each data CQE uses IORING_CQE_F_MORE and stores
 * the corresponding logical stream offset in the ZCRX CQE auxiliary field.
 *
 * Return: number of bytes consumed or a negative errno.
 */
int io_uring_cmd_zcrx_recv(struct io_uring_cmd *cmd,
			   struct io_uring_zcrx_ifq *ifq,
			   struct socket *sock, unsigned int len,
			   u64 stream_offset, unsigned int issue_flags);
#else
static inline int io_uring_cmd_zcrx_get(struct io_uring_cmd *cmd, u32 ifq_idx,
					struct io_uring_zcrx_ifq **ifq)
{
	return -EOPNOTSUPP;
}

static inline void io_uring_cmd_zcrx_put(struct io_uring_zcrx_ifq *ifq)
{
}

static inline int io_uring_cmd_zcrx_peek(struct io_uring_zcrx_ifq *ifq,
					 struct socket *sock, void *buf,
					 unsigned int len)
{
	return -EOPNOTSUPP;
}

static inline int io_uring_cmd_zcrx_consume(struct socket *sock,
					    unsigned int len)
{
	return -EOPNOTSUPP;
}

static inline int io_uring_cmd_zcrx_recv(struct io_uring_cmd *cmd,
					 struct io_uring_zcrx_ifq *ifq,
					 struct socket *sock, unsigned int len,
					 u64 stream_offset,
					 unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}
#endif

#endif /* _LINUX_IO_URING_ZCRX_CMD_H */
