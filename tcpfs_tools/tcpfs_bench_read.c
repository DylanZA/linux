// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "tcpfs_zcrx.h"

#ifndef O_DIRECT
#define O_DIRECT 00040000
#endif

#define DEFAULT_LEN 4096U
#define DEFAULT_ITERS 100U
#define DEFAULT_WARMUP 5U
#define DEFAULT_ALIGN 4096U

enum bench_mode {
	MODE_PREAD,
	MODE_URING,
};

struct bench_opts {
	const char *path;
	enum bench_mode mode;
	uint64_t len;
	uint64_t offset;
	unsigned int iters;
	unsigned int warmup;
	unsigned int align;
	bool direct;
	bool csv;
	const char *label;
	const char *ifname;
	unsigned int rxq;
};

struct bench_result {
	uint64_t bytes;
	double total_ms;
	double min_ms;
	double mean_ms;
	double p50_ms;
	double p90_ms;
	double p99_ms;
	double max_ms;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s -p path [options]\n"
		"\n"
		"  -p path       file to read\n"
		"  -m mode       pread or uring (default: pread)\n"
		"  -l len        bytes per read (default: %u)\n"
		"  -o offset     file offset (default: 0)\n"
		"  -i iters      measured iterations (default: %u)\n"
		"  -w warmup     warmup iterations (default: %u)\n"
		"  -d            open with O_DIRECT\n"
		"  -a align      buffer alignment (default: %u)\n"
		"  -L label      label printed in output\n"
		"  -I ifname     bind zcrx to a NIC (uring mode; default: NODEV)\n"
		"  -q rxq        NIC receive queue (default: 0)\n"
		"  -c            CSV output\n",
		prog, DEFAULT_LEN, DEFAULT_ITERS, DEFAULT_WARMUP,
		DEFAULT_ALIGN);
}

static int parse_u64(const char *s, uint64_t *out)
{
	char *end = NULL;
	unsigned long long val;

	errno = 0;
	val = strtoull(s, &end, 0);
	if (errno || !end || *end)
		return -EINVAL;
	*out = val;
	return 0;
}

static const char *mode_name(enum bench_mode mode)
{
	return mode == MODE_URING ? "uring" : "pread";
}

static int parse_mode(const char *s, enum bench_mode *mode)
{
	if (!strcmp(s, "pread")) {
		*mode = MODE_PREAD;
		return 0;
	}
	if (!strcmp(s, "uring")) {
		*mode = MODE_URING;
		return 0;
	}
	return -EINVAL;
}

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static int cmp_double(const void *a, const void *b)
{
	double da = *(const double *)a;
	double db = *(const double *)b;

	return (da > db) - (da < db);
}

static double percentile(const double *samples, unsigned int nr, double pct)
{
	unsigned int idx;

	if (!nr)
		return 0.0;
	idx = (unsigned int)ceil((pct / 100.0) * nr);
	if (!idx)
		idx = 1;
	if (idx > nr)
		idx = nr;
	return samples[idx - 1];
}

static int do_pread(int fd, void *buf, size_t len, uint64_t offset)
{
	ssize_t ret;

	ret = pread(fd, buf, len, offset);
	if (ret < 0)
		return -errno;
	return ret;
}

static int do_uring_read(struct tcpfs_zcrx *zc, int fd, size_t len,
			 uint64_t offset)
{
	return tcpfs_zcrx_read(zc, fd, NULL, len, offset);
}

static int run_one_read(const struct bench_opts *opts, int fd, void *buf,
			struct tcpfs_zcrx *zc)
{
	if (opts->mode == MODE_URING)
		return do_uring_read(zc, fd, opts->len, opts->offset);
	return do_pread(fd, buf, opts->len, opts->offset);
}

static int run_bench(const struct bench_opts *opts, struct bench_result *res)
{
	struct tcpfs_zcrx zc = { };
	double *samples;
	void *buf = NULL;
	int open_flags = O_RDONLY;
	bool ring_ready = false;
	int fd = -1;
	int ret = 0;
	unsigned int i;

	if (opts->direct || opts->mode == MODE_URING)
		open_flags |= O_DIRECT;

	if (opts->mode == MODE_PREAD) {
		ret = posix_memalign(&buf, opts->align, opts->len);
		if (ret)
			return -ret;
		memset(buf, 0, opts->len);
	}

	samples = calloc(opts->iters, sizeof(*samples));
	if (!samples) {
		ret = -ENOMEM;
		goto out;
	}

	fd = open(opts->path, open_flags);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}

	if (opts->mode == MODE_URING) {
		unsigned int ifindex = 0;

		if (opts->ifname) {
			ifindex = if_nametoindex(opts->ifname);
			if (!ifindex) {
				ret = -ENODEV;
				goto out;
			}
		}
		ret = tcpfs_zcrx_setup_ifq(&zc, opts->len, ifindex, opts->rxq);
		if (ret)
			goto out;
		ring_ready = true;
	}

	for (i = 0; i < opts->warmup; i++) {
		ret = run_one_read(opts, fd, buf, &zc);
		if (ret < 0)
			goto out;
	}

	res->bytes = 0;
	res->total_ms = 0.0;
	for (i = 0; i < opts->iters; i++) {
		double start = now_ms();
		double end;

		ret = run_one_read(opts, fd, buf, &zc);
		end = now_ms();
		if (ret < 0)
			goto out;
		samples[i] = end - start;
		res->total_ms += samples[i];
		res->bytes += ret;
	}

	qsort(samples, opts->iters, sizeof(*samples), cmp_double);
	res->min_ms = samples[0];
	res->max_ms = samples[opts->iters - 1];
	res->mean_ms = res->total_ms / opts->iters;
	res->p50_ms = percentile(samples, opts->iters, 50.0);
	res->p90_ms = percentile(samples, opts->iters, 90.0);
	res->p99_ms = percentile(samples, opts->iters, 99.0);
	ret = 0;
	if (opts->mode == MODE_URING) {
		fprintf(stderr, "zcrx_if=%s rxq=%u ring_flags=%#x",
			opts->ifname ?: "NODEV", opts->rxq, zc.setup_flags);
		fprintf(stderr, " ring=single-issuer,defer-taskrun");
		fprintf(stderr, " fragments=%u copy_count=%" PRIu64,
			zc.last_fragments,
			tcpfs_zcrx_copy_count(&zc));
		fprintf(stderr, " copy_bytes=%" PRIu64 "\n",
			tcpfs_zcrx_copy_bytes(&zc));
	}

out:
	if (ring_ready)
		tcpfs_zcrx_teardown(&zc);
	if (fd >= 0)
		close(fd);
	free(samples);
	free(buf);
	return ret;
}

static void print_result(const struct bench_opts *opts,
			 const struct bench_result *res)
{
	double mib = (double)res->bytes / (1024.0 * 1024.0);
	double throughput = res->total_ms > 0.0 ? mib / (res->total_ms / 1000.0) :
			     0.0;

	if (opts->csv) {
		printf("label,path,mode,direct,len,offset,iters,warmup,bytes,"
		       "total_ms,min_ms,mean_ms,p50_ms,p90_ms,p99_ms,max_ms,"
		       "mib_s\n");
		printf("%s,%s,%s,%u,%" PRIu64 ",%" PRIu64 ",%u,%u,%" PRIu64
		       ",%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		       opts->label ?: "", opts->path, mode_name(opts->mode),
		       opts->direct, opts->len, opts->offset, opts->iters,
		       opts->warmup, res->bytes, res->total_ms, res->min_ms,
		       res->mean_ms, res->p50_ms, res->p90_ms, res->p99_ms,
		       res->max_ms, throughput);
		return;
	}

	printf("label=%s path=%s mode=%s direct=%u len=%" PRIu64
	       " offset=%" PRIu64 " iters=%u warmup=%u\n",
	       opts->label ?: "", opts->path, mode_name(opts->mode),
	       opts->direct, opts->len, opts->offset, opts->iters,
	       opts->warmup);
	printf("bytes=%" PRIu64 " total_ms=%.3f mib_s=%.3f\n",
	       res->bytes, res->total_ms, throughput);
	printf("lat_ms min=%.3f mean=%.3f p50=%.3f p90=%.3f p99=%.3f max=%.3f\n",
	       res->min_ms, res->mean_ms, res->p50_ms, res->p90_ms,
	       res->p99_ms, res->max_ms);
}

int main(int argc, char **argv)
{
	struct bench_opts opts = {
		.mode = MODE_PREAD,
		.len = DEFAULT_LEN,
		.iters = DEFAULT_ITERS,
		.warmup = DEFAULT_WARMUP,
		.align = DEFAULT_ALIGN,
	};
	struct bench_result res = {};
	uint64_t tmp;
	int opt;
	int ret;

	while ((opt = getopt(argc, argv, "hp:m:l:o:i:w:a:L:I:q:dc")) != -1) {
		switch (opt) {
		case 'p':
			opts.path = optarg;
			break;
		case 'm':
			if (parse_mode(optarg, &opts.mode))
				goto bad_args;
			break;
		case 'l':
			if (parse_u64(optarg, &opts.len))
				goto bad_args;
			break;
		case 'o':
			if (parse_u64(optarg, &opts.offset))
				goto bad_args;
			break;
		case 'i':
			if (parse_u64(optarg, &tmp) || !tmp || tmp > UINT_MAX)
				goto bad_args;
			opts.iters = tmp;
			break;
		case 'w':
			if (parse_u64(optarg, &tmp) || tmp > UINT_MAX)
				goto bad_args;
			opts.warmup = tmp;
			break;
		case 'a':
			if (parse_u64(optarg, &tmp) || !tmp || tmp > UINT_MAX)
				goto bad_args;
			opts.align = tmp;
			break;
		case 'L':
			opts.label = optarg;
			break;
		case 'I':
			opts.ifname = optarg;
			break;
		case 'q':
			if (parse_u64(optarg, &tmp) || tmp > UINT_MAX)
				goto bad_args;
			opts.rxq = tmp;
			break;
		case 'd':
			opts.direct = true;
			break;
		case 'c':
			opts.csv = true;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			goto bad_args;
		}
	}

	if (!opts.path || !opts.len || opts.len > UINT_MAX)
		goto bad_args;
	if (opts.mode == MODE_URING && !opts.direct)
		opts.direct = true;

	ret = run_bench(&opts, &res);
	if (ret) {
		fprintf(stderr, "%s %s: %s\n", mode_name(opts.mode), opts.path,
			strerror(-ret));
		return 1;
	}
	print_result(&opts, &res);
	return 0;

bad_args:
	usage(argv[0]);
	return 2;
}
