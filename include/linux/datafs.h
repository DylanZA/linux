/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_DATAFS_H
#define _LINUX_DATAFS_H

#include <linux/types.h>

#define TCPFS_NAME_LEN		32
#define TCPFS_MOUNT_ARG_MAX	128
#define TCPFS_PATH_MAX		512
#define TCPFS_PAYLOAD_MAX	4096

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
	/*
	 * Inspect the receive window and identify one response.  The callback is
	 * passed a receive-only context with id == 0.  It sets result.id to the
	 * request id, frame_len to the bytes to retire, and rx_need when more
	 * bytes are required; -EAGAIN requests another invocation after rx_need
	 * bytes are available.
	 */
	int (*recv_response)(struct tcpfs_recv_response_ctx *ctx);
	/* Return the bytes to pass to handle_response, or zero if incomplete. */
	int (*unframe_rx)(const struct tcpfs_unframe_rx_ctx *ctx);
	int (*handle_response)(struct tcpfs_handle_response_ctx *ctx);
	int (*loan_socket)(struct tcpfs_loan_socket_ctx *ctx);
	void (*return_socket)(struct tcpfs_return_socket_ctx *ctx);
};

struct tcpfs_bpf_ops;

struct tcpfs_bpf_ops *tcpfs_bpf_get(const char *name);
struct tcpfs_bpf_ops *tcpfs_bpf_get_wait(const char *name,
					 unsigned long timeout);
void tcpfs_bpf_put(struct tcpfs_bpf_ops *ops);
const struct tcpfs_ops *tcpfs_bpf_ops(const struct tcpfs_bpf_ops *ops);
int tcpfs_bpf_validate_ctx(const struct tcpfs_ctx *ctx);

#endif /* _LINUX_DATAFS_H */
