// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../include/uapi/linux/tcpfs.h"
#include "tcpfs_zcrx.h"

#ifndef O_DIRECT
#define O_DIRECT 00040000
#endif
#ifndef ZCRX_REG_NODEV
#define ZCRX_REG_NODEV 2U
#endif

#define DEFAULT_PATH "/tmp/tcpfs/links.txt"
#define DEFAULT_LEN 4096U
#define PAGE_BYTES 4096U
#define ZCRX_STREAM_WINDOW_PAGES 16384U
#define NIC_RX_RESERVE_PAGES 4352U
#define NODEV_RESERVE_PAGES 512U
#define CQE_BATCH 256U
#define MAX_RQ_ENTRIES 32768U
#define USER_DATA 0x74637066757a6372ULL
#define CANCEL_USER_DATA 0x7463706663616e63ULL
#define IORING_REGISTER_ZCRX_CTRL 36U
#define ZCRX_CTRL_FLUSH_RQ 0U
#define ZCRX_NOTIF_DESC_FLAG_STATS 1U

struct tcpfs_zcrx_ctrl {
	uint32_t zcrx_id;
	uint32_t op;
	uint64_t reserved[8];
};

struct tcpfs_zcrx_stats {
	uint64_t copy_count;
	uint64_t copy_bytes;
};

struct tcpfs_zcrx_notif_desc {
	uint64_t user_data;
	uint32_t type_mask;
	uint32_t flags;
	uint64_t stats_offset;
	uint64_t reserved[9];
};

/* Newer than the liburing checkout used to build these standalone tools. */
struct tcpfs_zcrx_ifq_reg {
	uint32_t if_idx;
	uint32_t if_rxq;
	uint32_t rq_entries;
	uint32_t flags;
	uint64_t area_ptr;
	uint64_t region_ptr;
	struct io_uring_zcrx_offsets offsets;
	uint32_t zcrx_id;
	uint32_t rx_buf_len;
	uint64_t notif_desc;
	uint64_t reserved[2];
};

#ifndef TCPFS_ZCRX_NO_MAIN
static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-C] [-p path] [-l len] [-o offset] [-I ifname] "
		"[-q rxq] [-n]\n"
		"  -C  cancel the command after submission\n"
		"  -I  bind ZCRX to a network interface (default: NODEV)\n"
		"  -q  receive queue for -I (default: 0)\n"
		"  -n  skip the O_DIRECT pread comparison\n", prog);
}

static int parse_u64(const char *s, uint64_t *out)
{
	char *end = NULL;
	unsigned long long value;

	errno = 0;
	value = strtoull(s, &end, 0);
	if (errno || !end || *end)
		return -EINVAL;
	*out = value;
	return 0;
}
#endif

static unsigned int roundup_pow2(unsigned int value)
{
	unsigned int result = 1;

	while (result < value)
		result <<= 1;
	return result;
}

int tcpfs_zcrx_setup_ifq(struct tcpfs_zcrx *zc, size_t len,
			 unsigned int ifindex, unsigned int rxq)
{
	struct io_uring_zcrx_area_reg area = { };
	struct tcpfs_zcrx_ifq_reg reg = { };
	struct tcpfs_zcrx_notif_desc notif = { };
	struct io_uring_region_desc region = { };
	struct io_uring_params params = { };
	unsigned int pages = (len + PAGE_BYTES - 1) / PAGE_BYTES;
	unsigned int reserve_pages = ifindex ? NIC_RX_RESERVE_PAGES :
						   NODEV_RESERVE_PAGES;
	unsigned int area_pages = (pages > ZCRX_STREAM_WINDOW_PAGES ?
				   ZCRX_STREAM_WINDOW_PAGES : pages) +
				  reserve_pages;
	unsigned int entries = roundup_pow2(area_pages + 1 > MAX_RQ_ENTRIES ?
					      MAX_RQ_ENTRIES : area_pages + 1);
	int ret;

	/* Keep request pages available after the NIC fills its receive ring. */
	zc->area_len = (size_t)area_pages * PAGE_BYTES;
	zc->area = mmap(NULL, zc->area_len, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (zc->area == MAP_FAILED)
		return -errno;

	/* offsets.rqes is cache-line aligned after the shared head/tail. */
	zc->rq_mem_len = 2 * PAGE_BYTES +
			 (size_t)entries * sizeof(struct io_uring_zcrx_rqe);
	zc->rq_mem_len = (zc->rq_mem_len + PAGE_BYTES - 1) &
			 ~(size_t)(PAGE_BYTES - 1);
	zc->rq_mem = mmap(NULL, zc->rq_mem_len, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (zc->rq_mem == MAP_FAILED) {
		ret = -errno;
		goto err_area;
	}

	params.flags = IORING_SETUP_SINGLE_ISSUER |
		       IORING_SETUP_DEFER_TASKRUN |
		       IORING_SETUP_CQE32 |
		       IORING_SETUP_CQSIZE;
	params.cq_entries = roundup_pow2(entries + 1);
	if (params.cq_entries < 8)
		params.cq_entries = 8;
	ret = io_uring_queue_init_params(8, &zc->ring, &params);
	if (ret) {
		fprintf(stderr, "io_uring setup: %s (%d)\n",
			strerror(-ret), ret);
		goto err_rq;
	}
	zc->setup_flags = params.flags;

	area.addr = (uintptr_t)zc->area;
	area.len = zc->area_len;
	region.user_addr = (uintptr_t)zc->rq_mem;
	region.size = zc->rq_mem_len;
	region.flags = IORING_MEM_REGION_TYPE_USER;
	notif.flags = ZCRX_NOTIF_DESC_FLAG_STATS;
	notif.stats_offset = zc->rq_mem_len - sizeof(struct tcpfs_zcrx_stats);
	reg.if_idx = ifindex;
	reg.if_rxq = rxq;
	reg.rq_entries = entries;
	reg.flags = ifindex ? 0 : ZCRX_REG_NODEV;
	reg.area_ptr = (uintptr_t)&area;
	reg.region_ptr = (uintptr_t)&region;
	reg.rx_buf_len = PAGE_BYTES;
	reg.notif_desc = (uintptr_t)&notif;

	ret = io_uring_register_ifq(&zc->ring,
				    (struct io_uring_zcrx_ifq_reg *)&reg);
	if (ret) {
		fprintf(stderr, "REGISTER_ZCRX_IFQ: %s (%d)\n",
			strerror(-ret), ret);
		goto err_ring;
	}

	zc->rq.khead = (uint32_t *)((char *)zc->rq_mem + reg.offsets.head);
	zc->rq.ktail = (uint32_t *)((char *)zc->rq_mem + reg.offsets.tail);
	zc->rq.rqes = (struct io_uring_zcrx_rqe *)
			((char *)zc->rq_mem + reg.offsets.rqes);
	zc->rq.rq_tail = 0;
	zc->rq.ring_entries = reg.rq_entries;
	zc->area_token = area.rq_area_token;
	zc->zcrx_id = reg.zcrx_id;
	zc->stats = (char *)zc->rq_mem + notif.stats_offset;
	return 0;

err_ring:
	io_uring_queue_exit(&zc->ring);
err_rq:
	munmap(zc->rq_mem, zc->rq_mem_len);
err_area:
	munmap(zc->area, zc->area_len);
	return ret;
}

int tcpfs_zcrx_setup(struct tcpfs_zcrx *zc, size_t len)
{
	return tcpfs_zcrx_setup_ifq(zc, len, 0, 0);
}

uint64_t tcpfs_zcrx_copy_count(const struct tcpfs_zcrx *zc)
{
	const struct tcpfs_zcrx_stats *stats = zc->stats;

	return stats ? __atomic_load_n(&stats->copy_count, __ATOMIC_RELAXED) : 0;
}

uint64_t tcpfs_zcrx_copy_bytes(const struct tcpfs_zcrx *zc)
{
	const struct tcpfs_zcrx_stats *stats = zc->stats;

	return stats ? __atomic_load_n(&stats->copy_bytes, __ATOMIC_RELAXED) : 0;
}

void tcpfs_zcrx_teardown(struct tcpfs_zcrx *zc)
{
	io_uring_queue_exit(&zc->ring);
	munmap(zc->rq_mem, zc->rq_mem_len);
	munmap(zc->area, zc->area_len);
}

static int flush_refill(struct tcpfs_zcrx *zc)
{
	struct tcpfs_zcrx_ctrl ctrl = {
		.zcrx_id = zc->zcrx_id,
		.op = ZCRX_CTRL_FLUSH_RQ,
	};
	int ret;

	ret = syscall(__NR_io_uring_register, zc->ring.ring_fd,
		      IORING_REGISTER_ZCRX_CTRL, &ctrl, 0);
	return ret < 0 ? -errno : ret;
}

static int return_page(struct tcpfs_zcrx *zc, uint64_t area_offset,
		       uint32_t len)
{
	struct io_uring_zcrx_rqe *rqe;
	uint32_t head = io_uring_smp_load_acquire(zc->rq.khead);
	unsigned int mask = zc->rq.ring_entries - 1;

	if (zc->rq.rq_tail - head == zc->rq.ring_entries) {
		int ret = flush_refill(zc);

		if (ret)
			return ret;
		head = io_uring_smp_load_acquire(zc->rq.khead);
		if (zc->rq.rq_tail - head == zc->rq.ring_entries)
			return -ENOSPC;
	}
	rqe = &zc->rq.rqes[zc->rq.rq_tail & mask];
	rqe->off = (area_offset & ~IORING_ZCRX_AREA_MASK) | zc->area_token;
	rqe->len = len;
	rqe->__pad = 0;
	io_uring_smp_store_release(zc->rq.ktail, ++zc->rq.rq_tail);
	return 0;
}

static int return_fragment(struct tcpfs_zcrx *zc, uint64_t area_offset,
			   uint32_t len)
{
	uint64_t token = area_offset & IORING_ZCRX_AREA_MASK;
	uint64_t offset = area_offset & ~IORING_ZCRX_AREA_MASK;
	uint64_t end = offset + len;
	uint64_t first;
	int ret;

	if (!len)
		return -EINVAL;
	if (end < offset)
		return -EOVERFLOW;
	first = offset & ~(uint64_t)(PAGE_BYTES - 1);
	offset = (end - 1) & ~(uint64_t)(PAGE_BYTES - 1);
	for (;;) {
		ret = return_page(zc, token | offset, PAGE_BYTES);
		if (ret)
			return ret;
		if (offset == first)
			break;
		offset -= PAGE_BYTES;
	}
	return 0;
}

int tcpfs_zcrx_read(struct tcpfs_zcrx *zc, int fd, void *output, size_t len,
		    uint64_t request_offset)
{
	struct io_uring_sqe *sqe;
	size_t received = 0;
	int ret;

	zc->last_fragments = 0;
	sqe = io_uring_get_sqe(&zc->ring);
	if (!sqe)
		return -EAGAIN;
	io_uring_prep_uring_cmd(sqe, TCPFS_URING_CMD_READ_ZC, fd);
	sqe->len = len;
	sqe->addr3 = request_offset;
	sqe->zcrx_ifq_idx = zc->zcrx_id;
	sqe->user_data = USER_DATA;

	ret = io_uring_submit(&zc->ring);
	if (ret != 1)
		return ret < 0 ? ret : -EIO;

	for (;;) {
		struct io_uring_cqe *cqes[CQE_BATCH];
		struct io_uring_cqe *cqe;
		unsigned int count, i;
		bool done = false;

		ret = io_uring_wait_cqe(&zc->ring, &cqe);
		if (ret)
			return ret;
		count = io_uring_peek_batch_cqe(&zc->ring, cqes, CQE_BATCH);
		if (!count)
			return -EIO;

		for (i = 0; i < count; i++) {
			const struct tcpfs_uring_zc_cqe *zcqe;
			uint64_t area_off, output_off;

			cqe = cqes[i];
			if (cqe->user_data != USER_DATA) {
				ret = -EPROTO;
				break;
			}
			if (!(cqe->flags & IORING_CQE_F_MORE)) {
				ret = cqe->res;
				if (ret >= 0 && (size_t)ret != received)
					ret = -EPROTO;
				done = true;
				break;
			}

			zcqe = (const void *)(cqe + 1);
			area_off = zcqe->area_offset & ~IORING_ZCRX_AREA_MASK;
			if (cqe->res <= 0 || zcqe->file_offset < request_offset) {
				ret = -EPROTO;
				break;
			}
			output_off = zcqe->file_offset - request_offset;
			if (area_off > zc->area_len ||
			    (size_t)cqe->res > zc->area_len - area_off ||
			    output_off > len || (size_t)cqe->res > len - output_off ||
			    received > len - (size_t)cqe->res) {
				ret = -EOVERFLOW;
				break;
			}
			if (output)
				memcpy((char *)output + output_off,
				       (char *)zc->area + area_off, cqe->res);
			received += cqe->res;
			zc->last_fragments++;
			ret = return_fragment(zc, zcqe->area_offset, cqe->res);
			if (ret)
				break;
		}
		io_uring_cq_advance(&zc->ring, i < count ? i + 1 : count);
		if (ret < 0)
			return ret;
		if (done)
			return flush_refill(zc) ?: ret;
	}
}

#ifndef TCPFS_ZCRX_NO_MAIN
static int tcpfs_zcrx_cancel_read(struct tcpfs_zcrx *zc, int fd, size_t len,
				  uint64_t request_offset)
{
	int command_res = INT_MIN, cancel_res = INT_MIN;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(&zc->ring);
	if (!sqe)
		return -EAGAIN;
	io_uring_prep_uring_cmd(sqe, TCPFS_URING_CMD_READ_ZC, fd);
	sqe->len = len;
	sqe->addr3 = request_offset;
	sqe->zcrx_ifq_idx = zc->zcrx_id;
	sqe->user_data = USER_DATA;
	ret = io_uring_submit(&zc->ring);
	if (ret != 1)
		return ret < 0 ? ret : -EIO;

	/* Let the request reach the fixture before asking io_uring to cancel it. */
	usleep(50000);
	sqe = io_uring_get_sqe(&zc->ring);
	if (!sqe)
		return -EAGAIN;
	io_uring_prep_cancel64(sqe, USER_DATA, 0);
	sqe->user_data = CANCEL_USER_DATA;
	ret = io_uring_submit(&zc->ring);
	if (ret != 1)
		return ret < 0 ? ret : -EIO;

	while (command_res == INT_MIN || cancel_res == INT_MIN) {
		struct io_uring_cqe *cqe;
		unsigned int flags;

		ret = io_uring_wait_cqe(&zc->ring, &cqe);
		if (ret)
			return ret;
		flags = cqe->flags;
		if (cqe->user_data == USER_DATA) {
			if (flags & IORING_CQE_F_MORE) {
				const struct tcpfs_uring_zc_cqe *zcqe =
					(const void *)(cqe + 1);

				ret = cqe->res > 0 ?
					return_fragment(zc, zcqe->area_offset, cqe->res) :
					-EPROTO;
			} else {
				command_res = cqe->res;
				ret = 0;
			}
		} else if (cqe->user_data == CANCEL_USER_DATA &&
			   !(flags & IORING_CQE_F_MORE)) {
			cancel_res = cqe->res;
			ret = 0;
		} else {
			ret = -EPROTO;
		}
		io_uring_cqe_seen(&zc->ring, cqe);
		if (ret)
			return ret;
	}

	ret = flush_refill(zc);
	if (ret)
		return ret;
	printf("cancellation command=%d cancel=%d\n", command_res, cancel_res);
	return command_res == -ECANCELED && !cancel_res ? 0 : -EIO;
}

static void dump_preview(const void *buf, size_t len)
{
	const unsigned char *bytes = buf;
	size_t i, count = len < 160 ? len : 160;

	printf("data (%zu byte preview):\n", count);
	for (i = 0; i < count; i++)
		putchar(bytes[i] == '\n' || bytes[i] == '\r' || bytes[i] == '\t' ||
			(bytes[i] >= 32 && bytes[i] < 127) ? bytes[i] : '.');
	if (count && bytes[count - 1] != '\n')
		putchar('\n');
}

int main(int argc, char **argv)
{
	const char *path = DEFAULT_PATH;
	const char *ifname = NULL;
	uint64_t offset = 0, len64 = DEFAULT_LEN;
	struct tcpfs_zcrx zc = { };
	unsigned int rxq = 0;
	bool compare = true;
	bool cancel = false;
	void *output = NULL, *expected = NULL;
	ssize_t expected_len = -1;
	int fd = -1, opt, ret;

	while ((opt = getopt(argc, argv, "Chp:l:o:I:q:n")) != -1) {
		switch (opt) {
		case 'C':
			cancel = true;
			compare = false;
			break;
		case 'p':
			path = optarg;
			break;
		case 'l':
			if (parse_u64(optarg, &len64))
				goto bad_args;
			break;
		case 'o':
			if (parse_u64(optarg, &offset))
				goto bad_args;
			break;
		case 'I':
			ifname = optarg;
			break;
		case 'q': {
			uint64_t value;

			if (parse_u64(optarg, &value) || value > UINT_MAX)
				goto bad_args;
			rxq = value;
			break;
		}
		case 'n':
			compare = false;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			goto bad_args;
		}
	}
	if (!len64 || len64 > UINT32_MAX)
		goto bad_args;
	if (posix_memalign(&output, PAGE_BYTES, len64) ||
	    (compare && posix_memalign(&expected, PAGE_BYTES, len64))) {
		fprintf(stderr, "buffer allocation failed\n");
		return 1;
	}
	memset(output, 0xa5, len64);

	fd = open(path, O_RDONLY | O_DIRECT);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 1;
	}
	/* A bound NIC ZCRX queue cannot service an ordinary recvmsg(). */
	if (compare) {
		expected_len = pread(fd, expected, len64, offset);
		if (expected_len < 0) {
			fprintf(stderr, "reference pread: %s\n", strerror(errno));
			return 1;
		}
	}
	if (ifname) {
		unsigned int ifindex = if_nametoindex(ifname);

		if (!ifindex) {
			fprintf(stderr, "unknown interface %s\n", ifname);
			return 1;
		}
		ret = tcpfs_zcrx_setup_ifq(&zc, len64, ifindex, rxq);
	} else {
		ret = tcpfs_zcrx_setup(&zc, len64);
	}
	if (ret) {
		fprintf(stderr, "%s zcrx setup: %s (%d)\n",
			ifname ?: "NODEV", strerror(-ret), ret);
		return 1;
	}
	printf("zcrx source=%s rxq=%u\n", ifname ?: "NODEV", rxq);
	if (cancel) {
		ret = tcpfs_zcrx_cancel_read(&zc, fd, len64, offset);
		if (ret)
			fprintf(stderr, "cancel test: %s (%d)\n",
				strerror(-ret), ret);
		tcpfs_zcrx_teardown(&zc);
		close(fd);
		free(output);
		return ret ? 1 : 0;
	}
	ret = tcpfs_zcrx_read(&zc, fd, output, len64, offset);
	printf("uring_cmd total=%d\n", ret);
	if (ret < 0) {
		fprintf(stderr, "uring_cmd: %s\n", strerror(-ret));
		return 1;
	}
	dump_preview(output, ret);

	if (compare) {
		if (expected_len != ret || memcmp(output, expected, ret)) {
			fprintf(stderr,
				"comparison failed: uring=%d pread=%zd (%s)\n",
				ret, expected_len, expected_len != ret ?
				"length mismatch" : "data mismatch");
			return 1;
		}
		printf("comparison ok (%d bytes)\n", ret);
	}
	printf("zcrx copies=%" PRIu64 " bytes=%" PRIu64 "\n",
	       tcpfs_zcrx_copy_count(&zc), tcpfs_zcrx_copy_bytes(&zc));
	printf("zcrx fragments=%u\n", zc.last_fragments);

	tcpfs_zcrx_teardown(&zc);
	close(fd);
	free(expected);
	free(output);
	return 0;

bad_args:
	usage(argv[0]);
	return 2;
}
#endif
