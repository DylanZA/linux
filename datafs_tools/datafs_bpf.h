/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TCPFS_BPF_H
#define TCPFS_BPF_H

/* Keep these declarations in sync with include/linux/datafs.h. */
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
	TCPFS_RESULT_CONTINUE	= 5,
};

enum tcpfs_result_flags {
	TCPFS_RESULT_F_SIZE_VALID	= 1U << 0,
};

#define TCPFS_RESULT_F_MASK	TCPFS_RESULT_F_SIZE_VALID

enum tcpfs_rx_run_flags {
	TCPFS_RX_RUN_F_FRAME_END	= 1U << 0,
};

#define TCPFS_RX_RUN_F_MASK	TCPFS_RX_RUN_F_FRAME_END

struct tcpfs_rx_run {
	__u64 data_len;
	__u64 wire_len;
	__u32 rx_offset;
	__u32 flags;
};

enum tcpfs_conn_style {
	TCPFS_CONN_NEW		= 1,
	TCPFS_CONN_SERIAL	= 2,
	TCPFS_CONN_OVERLAP	= 3,
};

struct bpf_map {
	__u8 __opaque;
};

struct tcpfs_socket_loan {
	__u64 id;
	__u64 ino;
	__u64 offset;
	__u64 len;
	__u32 path_len;
	__s32 error;
	__u32 socket_key;
	__u32 socket_returned;
	char path[TCPFS_PATH_MAX];
	void *sk;
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
	__u32 flags;
	struct tcpfs_rx_run rx_run;
	__u8 payload[TCPFS_PAYLOAD_MAX];
};

struct tcpfs_unframe_rx_ctx {
	const __u8 *data;
	__u32 len;
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
	__u32 rx_need;
	__s32 error;
	__u32 mount_arg_len;
	char path[TCPFS_PATH_MAX];
	char mount_arg[TCPFS_MOUNT_ARG_MAX];
	__u8 payload[TCPFS_PAYLOAD_MAX];
	__u8 rx[TCPFS_PAYLOAD_MAX];
	struct tcpfs_result result;
};

struct tcpfs_build_request_ctx {
	const struct tcpfs_ctx *input;
	struct tcpfs_ctx output;
};

struct tcpfs_frame_tx_ctx {
	const struct tcpfs_ctx *input;
	struct tcpfs_ctx output;
};

struct tcpfs_recv_response_ctx {
	const struct tcpfs_ctx *input;
	struct tcpfs_ctx output;
};

struct tcpfs_handle_response_ctx {
	const struct tcpfs_ctx *input;
	struct tcpfs_ctx output;
};

struct tcpfs_loan_socket_ctx {
	const struct tcpfs_socket_loan *input;
	struct tcpfs_socket_loan output;
};

struct tcpfs_return_socket_ctx {
	const struct tcpfs_socket_loan *input;
	struct tcpfs_socket_loan output;
};

struct tcpfs_ops {
	char name[TCPFS_NAME_LEN];
	__u32 conn_style;
	int (*build_request)(struct tcpfs_build_request_ctx *ctx);
	int (*frame_tx)(struct tcpfs_frame_tx_ctx *ctx);
	/* See include/linux/datafs.h for the receive-window contract. */
	int (*recv_response)(struct tcpfs_recv_response_ctx *ctx);
	/* Return the bytes to pass to handle_response, or zero if incomplete. */
	int (*unframe_rx)(const struct tcpfs_unframe_rx_ctx *ctx);
	int (*handle_response)(struct tcpfs_handle_response_ctx *ctx);
	int (*loan_socket)(struct tcpfs_loan_socket_ctx *ctx);
	void (*return_socket)(struct tcpfs_return_socket_ctx *ctx);
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
extern void bpf_tcpfs_socket_assign(struct tcpfs_socket_loan *loan,
				    struct bpf_map *sockmap__map,
				    __u32 key) __ksym;
extern int bpf_tcpfs_socket_return(struct tcpfs_socket_loan *loan,
				   struct bpf_map *sockmap__map) __ksym;

extern int bpf_tcpfs_unframe_rx_read_byte(
	const struct tcpfs_unframe_rx_ctx *ctx, __u32 offset) __ksym;
extern int bpf_tcpfs_unframe_rx_find(
	const struct tcpfs_unframe_rx_ctx *ctx, const void *needle,
	__u32 needle__sz) __ksym;
extern int
bpf_tcpfs_unframe_rx_find_str(const struct tcpfs_unframe_rx_ctx *ctx,
			      const char *needle__str) __ksym;

static __always_inline int
tcpfs_unframe_rx_read_byte(const struct tcpfs_unframe_rx_ctx *ctx,
				   __u32 offset)
{
	return bpf_tcpfs_unframe_rx_read_byte(ctx, offset);
}

static __always_inline int
tcpfs_unframe_rx_find_str(const struct tcpfs_unframe_rx_ctx *ctx,
				  const char *needle__str)
{
	return bpf_tcpfs_unframe_rx_find_str(ctx, needle__str);
}

/*
 * Common socket-loan pool size. Any provider that hands established TCP
 * sockets to datafs should provision its pool with at least this many slots.
 */
#define DATAFS_SOCKET_POOL_DEFAULT 1024

/*
 * DATAFS_DEFINE_SOCKET_LOAN() - Share one socket-loan pool across a provider.
 * @tag: bare identifier prefix used to name the generated programs (e.g.
 *       datafs_s3); must match the provider's own prefix.
 * @sockmap: identifier for the provider's SOCKMAP (socket loan storage).
 * @avail: identifier for the provider's queue of available socket keys.
 * @pool_max: maximum number of concurrent loaned sockets in this pool.
 *
 * Instantiates the two BPF_MAP_TYPE_SOCKMAP/QUEUE maps plus the
 * struct_ops/loan_socket and struct_ops/return_socket programs that drive the
 * loan lifecycle. Providers choose the exact map names so the Rust loader can
 * keep seeding them, and the callback names are uniquified with @tag so the
 * programs are distinct per provider object.
 */
#define DATAFS_DEFINE_SOCKET_LOAN(tag, sockmap, avail, pool_max)		\
struct {									\
	__uint(type, BPF_MAP_TYPE_SOCKMAP);					\
	__uint(max_entries, (pool_max));					\
	__type(key, __u32);							\
	__type(value, __u64);							\
} (sockmap) SEC(".maps");							\
struct {									\
	__uint(type, BPF_MAP_TYPE_QUEUE);					\
	__uint(max_entries, (pool_max));					\
	__type(value, __u32);							\
} (avail) SEC(".maps");								\
SEC("struct_ops/loan_socket")							\
int BPF_PROG(tag##_loan_socket, struct tcpfs_loan_socket_ctx *tctx)	\
{										\
	struct tcpfs_socket_loan *loan = &tctx->output;				\
	__u32 key;								\
	int ret;								\
										\
	ret = bpf_map_pop_elem(&(avail), &key);					\
	if (ret)								\
		return ret;							\
	loan->socket_key = key;							\
	bpf_tcpfs_socket_assign(loan, (struct bpf_map *)&(sockmap), key);	\
	if (loan->error) {							\
		ret = loan->error;						\
		bpf_map_push_elem(&(avail), &key, BPF_ANY);			\
		return ret;							\
	}									\
	return 0;								\
}										\
SEC("struct_ops/return_socket")							\
void BPF_PROG(tag##_return_socket, struct tcpfs_return_socket_ctx *tctx)	\
{										\
	struct tcpfs_socket_loan *loan = &tctx->output;				\
	__u32 key = loan->socket_key;						\
										\
	if (!bpf_tcpfs_socket_return(loan, (struct bpf_map *)&(sockmap)))	\
		bpf_map_push_elem(&(avail), &key, BPF_ANY);			\
}

#endif /* TCPFS_BPF_H */
