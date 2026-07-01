/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TCPFS_BPF_H
#define TCPFS_BPF_H

/* Keep these declarations in sync with include/linux/tcpfs.h. */
#define TCPFS_NAME_LEN		32
#define TCPFS_MOUNT_ARG_MAX	128
#define TCPFS_PATH_MAX		512
#define TCPFS_PAYLOAD_MAX	4096

#ifndef BIT
#define BIT(nr)			(1U << (nr))
#endif

enum tcpfs_op {
	TCPFS_OP_LOOKUP		= 1,
	TCPFS_OP_GETATTR	= 2,
	TCPFS_OP_READDIR	= 3,
	TCPFS_OP_READ		= 4,
};

enum tcpfs_result_type {
	TCPFS_RESULT_NONE	= 0,
	TCPFS_RESULT_ATTR	= 1,
	TCPFS_RESULT_DIRENT	= 2,
	TCPFS_RESULT_DATA	= 3,
	TCPFS_RESULT_ERROR	= 4,
};

enum tcpfs_result_flags {
	TCPFS_RESULT_F_STREAM		= 1U << 0,
	TCPFS_RESULT_F_SIZE_VALID	= 1U << 1,
};

enum tcpfs_conn_style {
	TCPFS_CONN_NEW		= 1,
	TCPFS_CONN_SERIAL	= 2,
	TCPFS_CONN_OVERLAP	= 3,
};

struct tcpfs_result {
	__u64 id;
	__u64 ino;
	__u64 size;
	__u64 offset;
	__u32 mode;
	__s32 error;
	__u32 type;
	__u32 payload_len;
	__u32 rx_offset;
	__u32 flags;
	__u8 payload[TCPFS_PAYLOAD_MAX];
};

struct tcpfs_ctx {
	__u64 id;
	__u64 ino;
	__u64 parent_ino;
	__u64 offset;
	__u64 len;
	__u32 op;
	__u32 path_len;
	__u32 payload_len;
	__u32 rx_len;
	__u32 frame_len;
	__s32 error;
	__u32 mount_arg_len;
	char path[TCPFS_PATH_MAX];
	char mount_arg[TCPFS_MOUNT_ARG_MAX];
	__u8 payload[TCPFS_PAYLOAD_MAX];
	__u8 rx[TCPFS_PAYLOAD_MAX];
	struct tcpfs_result result;
};

struct tcpfs_ops {
	char name[TCPFS_NAME_LEN];
	__u32 conn_style;
	int (*build_request)(struct tcpfs_ctx *ctx);
	int (*frame_tx)(struct tcpfs_ctx *ctx);
	int (*unframe_rx)(struct tcpfs_ctx *ctx);
	int (*handle_response)(struct tcpfs_ctx *ctx);
	int (*on_unsolicited)(struct tcpfs_ctx *ctx);
};

extern int bpf_tcpfs_payload_append(struct tcpfs_ctx *ctx, const void *src,
				    __u32 src__sz) __ksym;
extern int bpf_tcpfs_payload_write(struct tcpfs_ctx *ctx, __u32 offset,
				   const void *src, __u32 src__sz) __ksym;
extern int bpf_tcpfs_payload_append_str(struct tcpfs_ctx *ctx,
					const char *src__str) __ksym;
extern int bpf_tcpfs_payload_append_mount_arg(struct tcpfs_ctx *ctx) __ksym;
extern int bpf_tcpfs_payload_append_path(struct tcpfs_ctx *ctx) __ksym;
extern int bpf_tcpfs_payload_append_u64(struct tcpfs_ctx *ctx,
					__u64 value) __ksym;
extern int bpf_tcpfs_ctx_read_byte(struct tcpfs_ctx *ctx, __u32 offset) __ksym;
extern __s64 bpf_tcpfs_ctx_read_be32(struct tcpfs_ctx *ctx,
				     __u32 offset) __ksym;
extern int bpf_tcpfs_result_append(struct tcpfs_ctx *ctx, const void *src,
				   __u32 src__sz) __ksym;
extern int bpf_tcpfs_result_append_rx(struct tcpfs_ctx *ctx, __u32 offset,
				      __u32 len) __ksym;
extern int bpf_tcpfs_rx_find_from(struct tcpfs_ctx *ctx, __u32 offset,
				  const void *needle,
				  __u32 needle__sz) __ksym;
extern int bpf_tcpfs_rx_find(struct tcpfs_ctx *ctx, const void *needle,
			     __u32 needle__sz) __ksym;
extern int bpf_tcpfs_rx_find_str_from(struct tcpfs_ctx *ctx, __u32 offset,
				      const char *needle__str) __ksym;
extern int bpf_tcpfs_rx_find_str(struct tcpfs_ctx *ctx,
				 const char *needle__str) __ksym;
extern int bpf_tcpfs_rx_parse_u64(struct tcpfs_ctx *ctx, __u32 offset,
				  __u64 *value) __ksym;

#endif /* TCPFS_BPF_H */
