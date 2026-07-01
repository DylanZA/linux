/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TCPFS_ZCRX_H
#define TCPFS_ZCRX_H

#include <stddef.h>
#include <stdint.h>

#include <liburing.h>

struct tcpfs_zcrx {
	struct io_uring ring;
	struct io_uring_zcrx_rq rq;
	void *area;
	size_t area_len;
	void *rq_mem;
	size_t rq_mem_len;
	uint64_t area_token;
	uint32_t zcrx_id;
	uint32_t last_fragments;
	uint32_t setup_flags;
	void *stats;
};

int tcpfs_zcrx_setup(struct tcpfs_zcrx *zc, size_t len);
int tcpfs_zcrx_setup_ifq(struct tcpfs_zcrx *zc, size_t len,
			 unsigned int ifindex, unsigned int rxq);
void tcpfs_zcrx_teardown(struct tcpfs_zcrx *zc);
int tcpfs_zcrx_read(struct tcpfs_zcrx *zc, int fd, void *output, size_t len,
		    uint64_t request_offset);
uint64_t tcpfs_zcrx_copy_count(const struct tcpfs_zcrx *zc);
uint64_t tcpfs_zcrx_copy_bytes(const struct tcpfs_zcrx *zc);

#endif /* TCPFS_ZCRX_H */
