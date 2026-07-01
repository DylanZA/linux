// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>

static volatile sig_atomic_t exiting;

static int libbpf_log(enum libbpf_print_level level, const char *fmt,
		      va_list args)
{
	if (level == LIBBPF_DEBUG && !getenv("TCPFS_LOADER_DEBUG"))
		return 0;

	return vfprintf(stderr, fmt, args);
}

static const char *default_bpf_path(const char *argv0)
{
	static char path[PATH_MAX];
	const char *slash;
	size_t dir_len;

	slash = strrchr(argv0, '/');
	if (!slash)
		return "tcpfs_s3.bpf.o";

	dir_len = slash - argv0;
	if (dir_len + sizeof("/tcpfs_s3.bpf.o") > sizeof(path))
		return "tcpfs_s3.bpf.o";

	memcpy(path, argv0, dir_len);
	snprintf(path + dir_len, sizeof(path) - dir_len, "/tcpfs_s3.bpf.o");
	return path;
}

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static void try_load_tcpfs_module(void)
{
	int ret;

	ret = system("modprobe tcpfs >/dev/null 2>&1");
	if (ret)
		fprintf(stderr, "warning: failed to modprobe tcpfs, continuing\n");
}

static int attach_struct_ops(const char *path, const char *map_name)
{
	struct bpf_object_open_opts open_opts = {
		.sz = sizeof(open_opts),
	};
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct bpf_map *map;
	int err = 0;

	obj = bpf_object__open_file(path, &open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
		return -errno;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "failed to load %s: %s\n", path, strerror(-err));
		goto out;
	}

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		err = -ENOENT;
		fprintf(stderr, "map %s not found in %s\n", map_name, path);
		goto out;
	}

	link = bpf_map__attach_struct_ops(map);
	if (!link) {
		err = -errno;
		fprintf(stderr, "failed to attach struct_ops %s: %s\n",
			map_name, strerror(errno));
		goto out;
	}

	printf("attached %s from %s\n", map_name, path);
	printf("keep this process running while tcpfs is mounted\n");
	while (!exiting)
		pause();

out:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return err;
}

int main(int argc, char **argv)
{
	const char *path = default_bpf_path(argv[0]);
	const char *map_name = "tcpfs_s3";
	int err;

	if (argc > 1)
		path = argv[1];
	if (argc > 2)
		map_name = argv[2];
	if (argc > 3) {
		fprintf(stderr, "usage: %s [bpf-object] [struct-ops-map]\n", argv[0]);
		return 2;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_log);

	if (bump_memlock_rlimit())
		fprintf(stderr, "warning: failed to raise RLIMIT_MEMLOCK: %s\n",
			strerror(errno));
	try_load_tcpfs_module();

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	err = attach_struct_ops(path, map_name);
	return err ? 1 : 0;
}
