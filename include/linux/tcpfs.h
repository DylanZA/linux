/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TCPFS_H
#define _LINUX_TCPFS_H

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

#endif /* _LINUX_TCPFS_H */
