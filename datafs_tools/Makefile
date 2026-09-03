# SPDX-License-Identifier: GPL-2.0

ROOT ?= ..
CLANG ?= clang
CARGO ?= cargo
LIBURING ?= $(HOME)/dev/liburing

BPF_OBJS := datafs_s3.bpf.o datafs_rest.bpf.o datafs_nfs.bpf.o datafs_smb.bpf.o \
	datafs_nfs_bad.bpf.o datafs_nfs_ovl.bpf.o datafs_nfs_serial.bpf.o
RUST_BINS := datafs_s3_loader datafs_rest_loader datafs_nfs_loader datafs_smb_loader \
	datafs_nfs_test_server datafs_smb_test_server
URING_BINS := datafs_uring_read
LIBBPF_OUT := $(abspath .libbpf)
LIBBPF_A := $(LIBBPF_OUT)/libbpf.a
LIBBPF_GEN_INCLUDE := $(ROOT)/tools/bpf/resolve_btfids/libbpf/include
LIBURING_A := $(LIBURING)/src/liburing.a

BPF_CFLAGS := -O2 -g -Wall -Wextra -Werror -Wno-unused-parameter \
	--target=bpf \
	-I$(LIBBPF_GEN_INCLUDE) \
	-I$(ROOT)/tools/lib \
	-I$(ROOT)/tools/include \
	-I$(ROOT)/tools/include/uapi

.PHONY: all check clean libbpf rust smoke-nfs smoke-rest smoke-smb smoke-s3 \
	smoke-s3

all: $(BPF_OBJS) $(LIBBPF_A) $(LIBURING_A) rust $(URING_BINS)

rust: $(LIBBPF_A) $(LIBURING_A)
	LIBURING=$(LIBURING) $(CARGO) build --release --offline
	@for bin in $(RUST_BINS); do ln -sfn target/release/$$bin $$bin; done

check: all
	LIBURING=$(LIBURING) $(CARGO) test --release --offline
	LIBURING=$(LIBURING) $(CARGO) clippy --all-targets --offline -- -D warnings
	$(CARGO) fmt -- --check
	PYTHONDONTWRITEBYTECODE=1 python3 datafs_rest_example.py --self-test
	bash -n run_datafs_smoke.sh datafs_smoke_guest.sh
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
		./datafs_nfs_test_server --write-expected "$$tmp"; \
		test "$$(wc -c < "$$tmp")" -eq 8192
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
		./datafs_smb_test_server --write-expected "$$tmp"; \
		test "$$(wc -c < "$$tmp")" -eq 8192

smoke-nfs: all
	./run_datafs_smoke.sh datafs-nfs

smoke-rest: all
	./run_datafs_smoke.sh datafs-rest

smoke-smb: all
	./run_datafs_smoke.sh datafs-smb

smoke-s3: all
	./run_datafs_smoke.sh datafs-s3

libbpf $(LIBBPF_A):
	mkdir -p $(LIBBPF_OUT)
	$(MAKE) -C $(ROOT)/tools/lib/bpf OUTPUT=$(LIBBPF_OUT)/

$(LIBURING_A):
	$(MAKE) -C $(LIBURING)

datafs_%.bpf.o: datafs_%.bpf.c datafs_bpf.h $(LIBBPF_A)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

datafs_nfs_bad.bpf.o: datafs_nfs.bpf.c datafs_bpf.h $(LIBBPF_A)
	$(CLANG) $(BPF_CFLAGS) -DTCPFS_TEST_OVERSIZED_RESULT -c $< -o $@

datafs_nfs_ovl.bpf.o: datafs_nfs.bpf.c datafs_bpf.h $(LIBBPF_A)
	$(CLANG) $(BPF_CFLAGS) -DTCPFS_TEST_CONN_OVERLAP -c $< -o $@

datafs_nfs_serial.bpf.o: datafs_nfs.bpf.c datafs_bpf.h $(LIBBPF_A)
	$(CLANG) $(BPF_CFLAGS) -DTCPFS_TEST_CONN_SERIAL -c $< -o $@

clean:
	$(RM) $(BPF_OBJS) $(RUST_BINS) $(URING_BINS)
	$(CARGO) clean
	$(MAKE) -C $(ROOT)/tools/lib/bpf OUTPUT=$(LIBBPF_OUT)/ clean

$(URING_BINS): %: %.c $(LIBURING_A)
	$(CC) -O2 -Wall -Wextra -Werror -I$(LIBURING)/src/include \
		$< $(LIBURING_A) -lpthread -o $@
