// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <liburing.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s --path PATH --expected PATH --length LEN "
		"[--offset OFFSET]\n", program);
}

static int parse_u64(const char *value, uint64_t *result)
{
	char *end;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 0);
	if (errno || !*value || *end)
		return -EINVAL;
	*result = parsed;
	return 0;
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "path", required_argument, NULL, 'p' },
		{ "expected", required_argument, NULL, 'e' },
		{ "length", required_argument, NULL, 'l' },
		{ "offset", required_argument, NULL, 'o' },
		{ }
	};
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	const char *path = NULL;
	const char *expected_path = NULL;
	uint64_t length = 0;
	uint64_t offset = 0;
	uint8_t *actual = NULL;
	uint8_t *expected = NULL;
	int path_fd = -1;
	int expected_fd = -1;
	int ret;
	int option;
	ssize_t expected_read;

	while ((option = getopt_long(argc, argv, "p:e:l:o:", options, NULL)) !=
	       -1) {
		switch (option) {
		case 'p':
			path = optarg;
			break;
		case 'e':
			expected_path = optarg;
			break;
		case 'l':
			ret = parse_u64(optarg, &length);
			if (ret)
				goto usage_error;
			break;
		case 'o':
			ret = parse_u64(optarg, &offset);
			if (ret)
				goto usage_error;
			break;
		default:
			goto usage_error;
		}
	}
	if (!path || !expected_path || !length || length > SIZE_MAX ||
	    length > INT_MAX)
		goto usage_error;

	ret = posix_memalign((void **)&actual, 4096, length);
	if (ret) {
		ret = -ret;
		goto out;
	}
	expected = malloc(length);
	if (!expected) {
		ret = -ENOMEM;
		goto out;
	}
	path_fd = open(path, O_RDONLY | O_DIRECT | O_CLOEXEC);
	if (path_fd < 0) {
		ret = -errno;
		goto out;
	}
	expected_fd = open(expected_path, O_RDONLY | O_CLOEXEC);
	if (expected_fd < 0) {
		ret = -errno;
		goto out;
	}
	expected_read = pread(expected_fd, expected, length, offset);
	if (expected_read < 0) {
		ret = -errno;
		goto out;
	}
	if ((uint64_t)expected_read != length) {
		ret = -EINVAL;
		goto out;
	}

	ret = io_uring_queue_init(2, &ring, 0);
	if (ret)
		goto out;
	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		ret = -EIO;
		goto out_ring;
	}
	io_uring_prep_read(sqe, path_fd, actual, length, offset);
	sqe->user_data = 1;
	ret = io_uring_submit(&ring);
	if (ret != 1) {
		if (ret >= 0)
			ret = -EIO;
		goto out_ring;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret)
		goto out_ring;
	ret = cqe->res;
	io_uring_cqe_seen(&ring, cqe);
	if ((uint64_t)ret != length) {
		if (ret >= 0)
			ret = -EIO;
		goto out_ring;
	}
	if (memcmp(actual, expected, length)) {
		ret = -EIO;
		goto out_ring;
	}
	printf("io_uring read completion ok (%llu bytes)\n",
	       (unsigned long long)length);
	ret = 0;

out_ring:
	io_uring_queue_exit(&ring);
out:
	if (ret < 0)
		fprintf(stderr, "datafs_uring_read: %s\n", strerror(-ret));
	if (path_fd >= 0)
		close(path_fd);
	if (expected_fd >= 0)
		close(expected_fd);
	free(actual);
	free(expected);
	return ret < 0 ? 1 : ret;

usage_error:
	usage(argv[0]);
	return 2;
}
