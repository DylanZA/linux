# SPDX-License-Identifier: GPL-2.0

ROOT ?= ..
CLANG ?= clang
CC ?= gcc
RM ?= rm -f
PYTHON ?= python3
LIBURING ?= $(HOME)/dev/liburing

BPF_OBJS := tcpfs_s3.bpf.o tcpfs_nfs.bpf.o
LOADERS := tcpfs_s3_loader tcpfs_nfs_loader
URING_SMOKE := tcpfs_uring_read_smoke
READ_BENCH := tcpfs_bench_read
ZCRX_HELPER := tcpfs_zcrx.o
LIBBPF_OUT := $(abspath .libbpf)
LIBBPF_A := $(LIBBPF_OUT)/libbpf.a
LIBBPF_INCLUDE := $(LIBBPF_OUT)
LIBBPF_GEN_INCLUDE := $(ROOT)/tools/bpf/resolve_btfids/libbpf/include
LIBURING_A := $(LIBURING)/src/liburing.a

BPF_CFLAGS := -O2 -g -Wall -Wextra -Werror -Wno-unused-parameter \
	--target=bpf \
	-I$(LIBBPF_GEN_INCLUDE) \
	-I$(ROOT)/tools/lib \
	-I$(ROOT)/tools/include \
	-I$(ROOT)/tools/include/uapi

USER_CFLAGS := -O2 -g -Wall -Wextra -Werror \
	-I$(LIBBPF_INCLUDE) \
	-I$(ROOT)/tools/lib \
	-I$(ROOT)/tools/include \
	-I$(ROOT)/tools/include/uapi

URING_CFLAGS := -O2 -g -Wall -Wextra -Werror \
	-I$(LIBURING)/src/include

USER_LDLIBS := $(LIBBPF_A) -lelf -lz

.PHONY: all check clean libbpf smoke-nfs smoke-s3-nodev smoke-s3-nic

all: $(BPF_OBJS) $(LOADERS) $(URING_SMOKE) $(READ_BENCH)

check: all
	bash -n run_tcpfs_smoke.sh tcpfs_smoke_guest.sh \
		tcpfs_bench_mount_tcpfs.sh tcpfs_bench_compare_s3.sh
	$(PYTHON) -m py_compile tcpfs_nfs_test_server.py
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
		$(PYTHON) tcpfs_nfs_test_server.py --write-expected "$$tmp"; \
		test "$$(wc -c < "$$tmp")" -eq 8192

smoke-nfs: all
	./run_tcpfs_smoke.sh nfs

smoke-s3-nodev: all
	./run_tcpfs_smoke.sh s3-nodev

smoke-s3-nic: all
	./run_tcpfs_smoke.sh s3-nic

libbpf $(LIBBPF_A):
	mkdir -p $(LIBBPF_OUT)
	$(MAKE) -C $(ROOT)/tools/lib/bpf OUTPUT=$(LIBBPF_OUT)/

$(LIBURING_A):
	$(MAKE) -C $(LIBURING)

tcpfs_%.bpf.o: tcpfs_%.bpf.c tcpfs_bpf.h $(LIBBPF_A)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

tcpfs_s3_loader: tcpfs_s3_loader.c $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

tcpfs_nfs_loader: tcpfs_s3_loader.c $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) \
		-DTCPFS_DEFAULT_BPF_OBJECT=\"tcpfs_nfs.bpf.o\" \
		-DTCPFS_DEFAULT_STRUCT_OPS=\"tcpfs_nfs\" \
		$< -o $@ $(USER_LDLIBS)

$(URING_SMOKE): tcpfs_uring_read_smoke.c tcpfs_zcrx.h \
		$(ROOT)/include/uapi/linux/tcpfs.h $(LIBURING_A)
	$(CC) $(URING_CFLAGS) $< -o $@ $(LIBURING_A)

$(ZCRX_HELPER): tcpfs_uring_read_smoke.c tcpfs_zcrx.h \
		$(ROOT)/include/uapi/linux/tcpfs.h
	$(CC) $(URING_CFLAGS) -DTCPFS_ZCRX_NO_MAIN -c $< -o $@

$(READ_BENCH): tcpfs_bench_read.c tcpfs_zcrx.h $(ZCRX_HELPER) $(LIBURING_A)
	$(CC) $(URING_CFLAGS) $< $(ZCRX_HELPER) -o $@ $(LIBURING_A) -lm

clean:
	$(RM) $(BPF_OBJS) $(LOADERS) $(URING_SMOKE) $(READ_BENCH) $(ZCRX_HELPER)
	$(MAKE) -C $(ROOT)/tools/lib/bpf OUTPUT=$(LIBBPF_OUT)/ clean
