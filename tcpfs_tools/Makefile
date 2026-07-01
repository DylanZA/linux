# SPDX-License-Identifier: GPL-2.0

ROOT ?= ..
CLANG ?= clang
CC ?= gcc
RM ?= rm -f

BPF_OBJ := tcpfs_s3.bpf.o
LOADER := tcpfs_s3_loader
LIBBPF_OUT := $(abspath .libbpf)
LIBBPF_A := $(LIBBPF_OUT)/libbpf.a
LIBBPF_INCLUDE := $(LIBBPF_OUT)
LIBBPF_GEN_INCLUDE := $(ROOT)/tools/bpf/resolve_btfids/libbpf/include

BPF_CFLAGS := -O2 -g --target=bpf \
	-I$(LIBBPF_GEN_INCLUDE) \
	-I$(ROOT)/tools/lib \
	-I$(ROOT)/tools/include \
	-I$(ROOT)/tools/include/uapi

USER_CFLAGS := -O2 -g -Wall -Wextra \
	-I$(LIBBPF_INCLUDE) \
	-I$(ROOT)/tools/lib \
	-I$(ROOT)/tools/include \
	-I$(ROOT)/tools/include/uapi

USER_LDLIBS := $(LIBBPF_A) -lelf -lz

.PHONY: all clean libbpf

all: $(BPF_OBJ) $(LOADER)

libbpf $(LIBBPF_A):
	mkdir -p $(LIBBPF_OUT)
	$(MAKE) -C $(ROOT)/tools/lib/bpf OUTPUT=$(LIBBPF_OUT)/

$(BPF_OBJ): tcpfs_s3.bpf.c $(LIBBPF_A)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LOADER): tcpfs_s3_loader.c $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

clean:
	$(RM) $(BPF_OBJ) $(LOADER)
	$(MAKE) -C $(ROOT)/tools/lib/bpf OUTPUT=$(LIBBPF_OUT)/ clean
