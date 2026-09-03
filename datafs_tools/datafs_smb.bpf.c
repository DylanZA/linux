// SPDX-License-Identifier: GPL-2.0
/*
 * Read-only SMB2.1 client for datafs.
 *
 * The mount argument is "server/share".  Each operation negotiates a fresh
 * anonymous guest session, connects to the share, opens the requested path,
 * and then returns CREATE metadata, a directory query, or file data.  This
 * deliberately does not implement credentials, signing, encryption, DFS, or
 * Unicode names outside ASCII.
 */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "datafs_bpf.h"

#define SMB2_NEGOTIATE		0
#define SMB2_SESSION_SETUP	1
#define SMB2_TREE_CONNECT	3
#define SMB2_CREATE		5
#define SMB2_READ		8
#define SMB2_QUERY_DIRECTORY	14

#define SMB2_STATUS_MORE_PROCESSING_REQUIRED	0xc0000016U
#define SMB2_STATUS_END_OF_FILE			0xc0000011U
#define SMB2_STATUS_NO_MORE_FILES		0x80000006U
#define SMB2_STATUS_ACCESS_DENIED		0xc0000022U
#define SMB2_STATUS_OBJECT_NAME_NOT_FOUND	0xc0000034U
#define SMB2_STATUS_OBJECT_PATH_NOT_FOUND	0xc000003aU
#define SMB2_STATUS_FILE_IS_A_DIRECTORY		0xc00000baU
#define SMB2_STATUS_NOT_A_DIRECTORY		0xc0000103U

#define SMB2_FILE_ATTRIBUTE_DIRECTORY	0x10
#define SMB2_FILE_READ_DATA		0x00000001
#define SMB2_FILE_READ_EA		0x00000008
#define SMB2_FILE_READ_ATTRIBUTES	0x00000080
#define SMB2_READ_CONTROL		0x00020000
#define SMB2_SYNCHRONIZE		0x00100000
#define SMB2_FILE_DIRECTORY_FILE	0x00000001
#define SMB2_FILE_OPEN			1
#define SMB2_SHARE_ALL			7
#define SMB2_RESTART_SCANS		1
#define SMB2_FILE_DIRECTORY_INFORMATION	1
#define SMB2_NEGOTIATE_SIGNING_REQUIRED	2

#define SMB2_HEADER_SIZE	64
#define SMB2_NBSS_SIZE		4
#define SMB2_READ_MAX		65536U
#define SMB2_DIR_MAX		2048U
#define SMB2_MAX_DIRENTS	64
#define TCPFS_EACCES		13
#define TCPFS_EAGAIN		11
#define TCPFS_EINVAL		22
#define TCPFS_EISDIR		21
#define TCPFS_ENOENT		2
#define TCPFS_ENOTDIR		20
#define TCPFS_EOPNOTSUPP	95
#define TCPFS_EPROTO		71
#define TCPFS_EREMOTEIO	121

#ifdef TCPFS_SMB_DEBUG
#define SMB_LOG(...) bpf_printk(__VA_ARGS__)
#else
#define SMB_LOG(...) do { } while (0)
#endif

struct smb_tx {
	struct tcpfs_ctx *ctx;
	__u32 pos;
	__s32 error;
};

static __always_inline void smb_tx_u8(struct smb_tx *tx, __u8 value)
{
	int ret;

	if (tx->error)
		return;
	ret = bpf_tcpfs_payload_append(tx->ctx, &value, sizeof(value));
	if (ret)
		tx->error = ret;
	else
		tx->pos++;
}

static __always_inline void smb_tx_le16(struct smb_tx *tx, __u16 value)
{
	smb_tx_u8(tx, value);
	smb_tx_u8(tx, value >> 8);
}

static __always_inline void smb_tx_le32(struct smb_tx *tx, __u32 value)
{
	smb_tx_le16(tx, value);
	smb_tx_le16(tx, value >> 16);
}

static __always_inline void smb_tx_le64(struct smb_tx *tx, __u64 value)
{
	smb_tx_le32(tx, value);
	smb_tx_le32(tx, value >> 32);
}

static __always_inline void smb_tx_zeroes(struct smb_tx *tx, __u32 count)
{
	__u32 i;

	for (i = 0; i < 16; i++) {
		if (i >= count)
			break;
		smb_tx_u8(tx, 0);
	}
}

static __always_inline void
smb_tx_header(struct smb_tx *tx, __u16 command, __u64 message_id,
	      __u32 tree_id, __u64 session_id)
{
	smb_tx_le32(tx, 0); /* NetBIOS session header, filled by frame_tx. */
	smb_tx_u8(tx, 0xfe);
	smb_tx_u8(tx, 'S');
	smb_tx_u8(tx, 'M');
	smb_tx_u8(tx, 'B');
	smb_tx_le16(tx, SMB2_HEADER_SIZE);
	smb_tx_le16(tx, 1); /* CreditCharge */
	smb_tx_le32(tx, 0); /* ChannelSequence/Reserved */
	smb_tx_le16(tx, command);
	smb_tx_le16(tx, 1); /* CreditRequest */
	smb_tx_le32(tx, 0); /* Flags */
	smb_tx_le32(tx, 0); /* NextCommand */
	smb_tx_le64(tx, message_id);
	smb_tx_le32(tx, 0xfeff); /* ProcessId */
	smb_tx_le32(tx, tree_id);
	smb_tx_le64(tx, session_id);
	smb_tx_zeroes(tx, 16); /* Signature */
}

static __always_inline void smb_build_negotiate(struct tcpfs_ctx *ctx)
{
	struct smb_tx tx = { .ctx = ctx };

	ctx->payload_len = 0;
	smb_tx_header(&tx, SMB2_NEGOTIATE, ctx->id << 4, 0, 0);
	smb_tx_le16(&tx, 36);
	smb_tx_le16(&tx, 1); /* DialectCount */
	smb_tx_le16(&tx, 1); /* Signing enabled, not required. */
	smb_tx_le16(&tx, 0);
	smb_tx_le32(&tx, 0);
	/* Stable nonzero client GUID. */
	smb_tx_le64(&tx, 0x74637066732d736dULL);
	smb_tx_le64(&tx, 0x622d636c69656e74ULL);
	smb_tx_le64(&tx, 0); /* ClientStartTime */
	smb_tx_le16(&tx, 0x0210);
	ctx->payload_len = tx.error ? 0 : tx.pos;
}

static __always_inline void smb_tx_ntlm_negotiate(struct smb_tx *tx)
{
	/* SPNEGO NegTokenInit containing a minimal NTLMSSP type-1 token. */
	__u8 prefix[] = {
		0x60, 0x40, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x02, 0xa0, 0x36, 0x30, 0x34, 0xa0, 0x0e,
		0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x22,
		0x04, 0x20,
	};
	__u32 i;

	for (i = 0; i < sizeof(prefix); i++)
		smb_tx_u8(tx, prefix[i]);
	smb_tx_u8(tx, 'N');
	smb_tx_u8(tx, 'T');
	smb_tx_u8(tx, 'L');
	smb_tx_u8(tx, 'M');
	smb_tx_u8(tx, 'S');
	smb_tx_u8(tx, 'S');
	smb_tx_u8(tx, 'P');
	smb_tx_u8(tx, 0);
	smb_tx_le32(tx, 1);
	smb_tx_le32(tx, 0x00088207);
	smb_tx_zeroes(tx, 16);
}

static __always_inline void smb_tx_ntlm_auth(struct smb_tx *tx)
{
	__u32 i;

	/* SPNEGO NegTokenResp containing an anonymous NTLMSSP type-3 token. */
	smb_tx_u8(tx, 0xa1);
	smb_tx_u8(tx, 0x46);
	smb_tx_u8(tx, 0x30);
	smb_tx_u8(tx, 0x44);
	smb_tx_u8(tx, 0xa2);
	smb_tx_u8(tx, 0x42);
	smb_tx_u8(tx, 0x04);
	smb_tx_u8(tx, 0x40);
	smb_tx_u8(tx, 'N');
	smb_tx_u8(tx, 'T');
	smb_tx_u8(tx, 'L');
	smb_tx_u8(tx, 'M');
	smb_tx_u8(tx, 'S');
	smb_tx_u8(tx, 'S');
	smb_tx_u8(tx, 'P');
	smb_tx_u8(tx, 0);
	smb_tx_le32(tx, 3);
	for (i = 0; i < 6; i++) {
		smb_tx_le16(tx, 0);
		smb_tx_le16(tx, 0);
		smb_tx_le32(tx, 64);
	}
	smb_tx_le32(tx, 0x00088a05); /* NTLMSSP_NEGOTIATE_ANONYMOUS */
}

static __always_inline void
smb_build_session_setup(struct tcpfs_ctx *ctx, __u64 message_id,
			__u64 session_id, __u32 authenticate)
{
	struct smb_tx tx = { .ctx = ctx };
	__u16 security_len = authenticate ? 72 : 66;

	ctx->payload_len = 0;
	smb_tx_header(&tx, SMB2_SESSION_SETUP, message_id, 0, session_id);
	smb_tx_le16(&tx, 25);
	smb_tx_u8(&tx, 0);
	smb_tx_u8(&tx, 1);
	smb_tx_le32(&tx, 0);
	smb_tx_le32(&tx, 0);
	smb_tx_le16(&tx, SMB2_HEADER_SIZE + 24);
	smb_tx_le16(&tx, security_len);
	smb_tx_le64(&tx, 0);
	if (authenticate)
		smb_tx_ntlm_auth(&tx);
	else
		smb_tx_ntlm_negotiate(&tx);
	ctx->payload_len = tx.error ? 0 : tx.pos;
}

struct smb_string_state {
	struct smb_tx tx;
	__u32 length;
	__u32 mount_arg;
};

static long smb_utf16_cb(__u32 i, void *data)
{
	struct smb_string_state *state = data;
	struct tcpfs_ctx *ctx = state->tx.ctx;
	__u32 base;
	int value;

	if (i >= state->length || state->tx.error)
		return 1;
	base = state->mount_arg ?
		__builtin_offsetof(struct tcpfs_ctx, mount_arg) :
		__builtin_offsetof(struct tcpfs_ctx, path);
	value = bpf_tcpfs_ctx_read_byte(ctx, base + i);
	if (value < 0) {
		state->tx.error = value;
		return 1;
	}
	if (!value) {
		state->tx.error = -TCPFS_EINVAL;
		return 1;
	}
	if (value == '/')
		value = '\\';
	smb_tx_le16(&state->tx, value);
	return 0;
}

static __always_inline void
smb_build_tree_connect(struct tcpfs_ctx *ctx, __u64 message_id,
		       __u64 session_id)
{
	struct smb_string_state state = {
		.tx = { .ctx = ctx },
		.length = ctx->mount_arg_len,
		.mount_arg = 1,
	};
	__u16 path_len = 4 + ctx->mount_arg_len * 2;

	ctx->payload_len = 0;
	smb_tx_header(&state.tx, SMB2_TREE_CONNECT, message_id, 0, session_id);
	smb_tx_le16(&state.tx, 9);
	smb_tx_le16(&state.tx, 0);
	smb_tx_le16(&state.tx, SMB2_HEADER_SIZE + 8);
	smb_tx_le16(&state.tx, path_len);
	smb_tx_le16(&state.tx, '\\');
	smb_tx_le16(&state.tx, '\\');
	bpf_loop(TCPFS_MOUNT_ARG_MAX, smb_utf16_cb, &state, 0);
	ctx->payload_len = state.tx.error ? 0 : state.tx.pos;
}

static __always_inline void
smb_build_create(struct tcpfs_ctx *ctx, __u64 message_id, __u32 tree_id,
		 __u64 session_id)
{
	struct smb_string_state state = {
		.tx = { .ctx = ctx },
		.length = ctx->path_len,
	};
	__u32 options = ctx->op == TCPFS_OP_READDIR ?
		SMB2_FILE_DIRECTORY_FILE : 0;

	ctx->payload_len = 0;
	smb_tx_header(&state.tx, SMB2_CREATE, message_id, tree_id, session_id);
	smb_tx_le16(&state.tx, 57);
	smb_tx_u8(&state.tx, 0);
	smb_tx_u8(&state.tx, 0);
	smb_tx_le32(&state.tx, 2); /* Impersonation */
	smb_tx_le64(&state.tx, 0);
	smb_tx_le64(&state.tx, 0);
	smb_tx_le32(&state.tx, SMB2_FILE_READ_DATA | SMB2_FILE_READ_EA |
			 SMB2_FILE_READ_ATTRIBUTES | SMB2_READ_CONTROL |
			 SMB2_SYNCHRONIZE);
	smb_tx_le32(&state.tx, 0);
	smb_tx_le32(&state.tx, SMB2_SHARE_ALL);
	smb_tx_le32(&state.tx, SMB2_FILE_OPEN);
	smb_tx_le32(&state.tx, options);
	smb_tx_le16(&state.tx, SMB2_HEADER_SIZE + 56);
	smb_tx_le16(&state.tx, ctx->path_len * 2);
	smb_tx_le32(&state.tx, 0);
	smb_tx_le32(&state.tx, 0);
	bpf_loop(TCPFS_PATH_MAX, smb_utf16_cb, &state, 0);
	ctx->payload_len = state.tx.error ? 0 : state.tx.pos;
}

static __always_inline void
smb_build_read(struct tcpfs_ctx *ctx, __u64 message_id, __u32 tree_id,
	       __u64 session_id, __u64 file_persistent, __u64 file_volatile)
{
	struct smb_tx tx = { .ctx = ctx };
	__u32 count = ctx->len > SMB2_READ_MAX ? SMB2_READ_MAX : ctx->len;

	ctx->payload_len = 0;
	smb_tx_header(&tx, SMB2_READ, message_id, tree_id, session_id);
	smb_tx_le16(&tx, 49);
	smb_tx_u8(&tx, 0);
	smb_tx_u8(&tx, 0);
	smb_tx_le32(&tx, count);
	smb_tx_le64(&tx, ctx->offset);
	smb_tx_le64(&tx, file_persistent);
	smb_tx_le64(&tx, file_volatile);
	smb_tx_le32(&tx, 0);
	smb_tx_le32(&tx, 0);
	smb_tx_le32(&tx, 0);
	smb_tx_le16(&tx, 0);
	smb_tx_le16(&tx, 0);
	ctx->payload_len = tx.error ? 0 : tx.pos;
}

static __always_inline void
smb_build_query_directory(struct tcpfs_ctx *ctx, __u64 message_id,
			  __u32 tree_id, __u64 session_id,
			  __u64 file_persistent, __u64 file_volatile)
{
	struct smb_tx tx = { .ctx = ctx };

	ctx->payload_len = 0;
	smb_tx_header(&tx, SMB2_QUERY_DIRECTORY, message_id, tree_id, session_id);
	smb_tx_le16(&tx, 33);
	smb_tx_u8(&tx, SMB2_FILE_DIRECTORY_INFORMATION);
	smb_tx_u8(&tx, SMB2_RESTART_SCANS);
	smb_tx_le32(&tx, 0);
	smb_tx_le64(&tx, file_persistent);
	smb_tx_le64(&tx, file_volatile);
	smb_tx_le16(&tx, SMB2_HEADER_SIZE + 32);
	smb_tx_le16(&tx, 2);
	smb_tx_le32(&tx, SMB2_DIR_MAX);
	smb_tx_le16(&tx, '*');
	ctx->payload_len = tx.error ? 0 : tx.pos;
}

static __always_inline int smb_rx_u8(struct tcpfs_ctx *ctx, __u32 offset)
{
	return bpf_tcpfs_ctx_read_byte(ctx,
		__builtin_offsetof(struct tcpfs_ctx, rx) + offset);
}

static __noinline int smb_request_header(struct tcpfs_ctx *ctx,
					 __u16 *command, __u64 *message_id)
{
	__u32 base = __builtin_offsetof(struct tcpfs_ctx, payload);
	__u64 value = 0;
	int byte, i;

	byte = bpf_tcpfs_ctx_read_byte(ctx, base + 16);
	if (byte < 0)
		return -TCPFS_EPROTO;
	*command = byte;
	byte = bpf_tcpfs_ctx_read_byte(ctx, base + 17);
	if (byte < 0)
		return -TCPFS_EPROTO;
	*command |= (__u16)byte << 8;
	for (i = 0; i < 8; i++) {
		byte = bpf_tcpfs_ctx_read_byte(ctx, base + 28 + i);
		if (byte < 0)
			return -TCPFS_EPROTO;
		value |= (__u64)byte << (i * 8);
	}
	*message_id = value;
	return 0;
}

static __noinline int smb_rx_le16(struct tcpfs_ctx *ctx, __u32 offset,
				  __u16 *value)
{
	int a = smb_rx_u8(ctx, offset);
	int b = smb_rx_u8(ctx, offset + 1);

	if (a < 0 || b < 0)
		return -TCPFS_EPROTO;
	*value = a | ((__u16)b << 8);
	return 0;
}

static __noinline int smb_rx_le32(struct tcpfs_ctx *ctx, __u32 offset,
				  __u32 *value)
{
	__u16 low, high;
	int ret;

	ret = smb_rx_le16(ctx, offset, &low);
	ret = ret ?: smb_rx_le16(ctx, offset + 2, &high);
	if (!ret)
		*value = low | ((__u32)high << 16);
	return ret;
}

static __noinline int smb_rx_le64(struct tcpfs_ctx *ctx, __u32 offset,
				  __u64 *value)
{
	__u32 low, high;
	int ret;

	ret = smb_rx_le32(ctx, offset, &low);
	ret = ret ?: smb_rx_le32(ctx, offset + 4, &high);
	if (!ret)
		*value = low | ((__u64)high << 32);
	return ret;
}

static __always_inline int smb_status_errno(__u32 status)
{
	switch (status) {
	case SMB2_STATUS_ACCESS_DENIED:
		return -TCPFS_EACCES;
	case SMB2_STATUS_OBJECT_NAME_NOT_FOUND:
	case SMB2_STATUS_OBJECT_PATH_NOT_FOUND:
		return -TCPFS_ENOENT;
	case SMB2_STATUS_FILE_IS_A_DIRECTORY:
		return -TCPFS_EISDIR;
	case SMB2_STATUS_NOT_A_DIRECTORY:
		return -TCPFS_ENOTDIR;
	default:
		return -TCPFS_EREMOTEIO;
	}
}

static __always_inline int smb_check_header(struct tcpfs_ctx *ctx,
					    __u16 *command,
					    __u32 *status)
{
	__u16 structure_size;
	int ret;

	if (ctx->rx_len < SMB2_NBSS_SIZE + SMB2_HEADER_SIZE ||
	    smb_rx_u8(ctx, 4) != 0xfe || smb_rx_u8(ctx, 5) != 'S' ||
	    smb_rx_u8(ctx, 6) != 'M' || smb_rx_u8(ctx, 7) != 'B')
		return -TCPFS_EPROTO;
	ret = smb_rx_le16(ctx, 8, &structure_size);
	ret = ret ?: smb_rx_le32(ctx, 12, status);
	ret = ret ?: smb_rx_le16(ctx, 16, command);
	if (ret || structure_size != SMB2_HEADER_SIZE)
		return -TCPFS_EPROTO;
	return 0;
}

static __always_inline int
smb_unframe_rx_u16(const struct tcpfs_unframe_rx_ctx *ctx, __u32 offset,
			   __u16 *value)
{
	int low = tcpfs_unframe_rx_read_byte(ctx, offset);
	int high = tcpfs_unframe_rx_read_byte(ctx, offset + 1);

	if (low < 0 || high < 0)
		return -TCPFS_EPROTO;
	*value = low | ((__u16)high << 8);
	return 0;
}

static __always_inline int
smb_unframe_rx_u32(const struct tcpfs_unframe_rx_ctx *ctx, __u32 offset,
			   __u32 *value)
{
	int byte0 = tcpfs_unframe_rx_read_byte(ctx, offset);
	int byte1 = tcpfs_unframe_rx_read_byte(ctx, offset + 1);
	int byte2 = tcpfs_unframe_rx_read_byte(ctx, offset + 2);
	int byte3 = tcpfs_unframe_rx_read_byte(ctx, offset + 3);

	if (byte0 < 0 || byte1 < 0 || byte2 < 0 || byte3 < 0)
		return -TCPFS_EPROTO;
	*value = byte0 | ((__u32)byte1 << 8) |
		 ((__u32)byte2 << 16) | ((__u32)byte3 << 24);
	return 0;
}

static __always_inline int
smb_unframe_rx_header(const struct tcpfs_unframe_rx_ctx *ctx,
			      __u16 *command, __u32 *status)
{
	__u16 structure_size;
	int ret;

	if (tcpfs_unframe_rx_read_byte(ctx, 4) != 0xfe ||
	    tcpfs_unframe_rx_read_byte(ctx, 5) != 'S' ||
	    tcpfs_unframe_rx_read_byte(ctx, 6) != 'M' ||
	    tcpfs_unframe_rx_read_byte(ctx, 7) != 'B')
		return -TCPFS_EPROTO;
	ret = smb_unframe_rx_u16(ctx, 8, &structure_size);
	ret = ret ?: smb_unframe_rx_u32(ctx, 12, status);
	ret = ret ?: smb_unframe_rx_u16(ctx, 16, command);
	if (ret || structure_size != SMB2_HEADER_SIZE)
		return -TCPFS_EPROTO;
	return 0;
}

static __always_inline void smb_continue(struct tcpfs_ctx *ctx)
{
	ctx->result.id = ctx->id;
	ctx->result.type = TCPFS_RESULT_CONTINUE;
}

static __always_inline int smb_create_result(struct tcpfs_ctx *ctx)
{
	__u64 size, ino;
	__u32 attrs;
	__u16 structure_size;
	int ret;

	ret = smb_rx_le16(ctx, 68, &structure_size);
	ret = ret ?: smb_rx_le64(ctx, 116, &size);
	ret = ret ?: smb_rx_le32(ctx, 124, &attrs);
	ret = ret ?: smb_rx_le64(ctx, 132, &ino);
	if (ret || structure_size != 89)
		return -TCPFS_EPROTO;
	ctx->result.id = ctx->id;
	ctx->result.type = TCPFS_RESULT_ATTR;
	ctx->result.flags = TCPFS_RESULT_F_SIZE_VALID;
	ctx->result.ino = ino ?: ctx->id + 1;
	ctx->result.size = size;
	ctx->result.mode = attrs & SMB2_FILE_ATTRIBUTE_DIRECTORY ?
		0040555 : 0100444;
	return 0;
}

struct smb_name_state {
	struct tcpfs_ctx *ctx;
	__u32 pos;
	__u32 chars;
	__s32 error;
};

static long smb_name_cb(__u32 i, void *data)
{
	struct smb_name_state *state = data;
	__u8 c;
	int low, high, ret;

	if (i >= state->chars || state->error)
		return 1;
	low = smb_rx_u8(state->ctx, state->pos + i * 2);
	high = smb_rx_u8(state->ctx, state->pos + i * 2 + 1);
	if (low <= 0 || high != 0 || low == '/' || low == '\\' || low == '\n') {
		state->error = -TCPFS_EOPNOTSUPP;
		return 1;
	}
	c = low;
	ret = bpf_tcpfs_result_append(state->ctx, &c, sizeof(c));
	if (ret) {
		state->error = ret;
		return 1;
	}
	return 0;
}

struct smb_dir_state {
	struct tcpfs_ctx *ctx;
	__u32 pos;
	__u32 end;
	__s32 error;
	__u32 done;
};

static long smb_dirent_cb(__u32 i, void *data)
{
	struct smb_dir_state *state = data;
	struct tcpfs_ctx *ctx = state->ctx;
	struct smb_name_state name = { .ctx = ctx };
	__u32 next, attrs, name_len;
	__u32 skip = 0;
	__u8 suffix;
	int first, second, ret;

	if (i >= SMB2_MAX_DIRENTS || state->error || state->done)
		return 1;
	if (state->pos > state->end || state->end - state->pos < 64) {
		state->error = -TCPFS_EPROTO;
		return 1;
	}
	ret = smb_rx_le32(ctx, state->pos, &next);
	ret = ret ?: smb_rx_le32(ctx, state->pos + 56, &attrs);
	ret = ret ?: smb_rx_le32(ctx, state->pos + 60, &name_len);
	if (ret || !name_len || (name_len & 1) || name_len > 510 ||
	    name_len > state->end - state->pos - 64) {
		state->error = -TCPFS_EPROTO;
		return 1;
	}
	name.pos = state->pos + 64;
	name.chars = name_len / 2;
	first = smb_rx_u8(ctx, name.pos);
	second = name_len >= 4 ? smb_rx_u8(ctx, name.pos + 2) : 0;
	if (first == '.' && (name_len == 2 || (name_len == 4 && second == '.')))
		skip = 1;
	if (!skip) {
		bpf_loop(255, smb_name_cb, &name, 0);
		if (name.error) {
			state->error = name.error;
			return 1;
		}
		if (attrs & SMB2_FILE_ATTRIBUTE_DIRECTORY) {
			suffix = '/';
			ret = bpf_tcpfs_result_append(ctx, &suffix, sizeof(suffix));
			if (ret)
				goto error;
		}
		suffix = '\n';
		ret = bpf_tcpfs_result_append(ctx, &suffix, sizeof(suffix));
		if (ret)
			goto error;
	}
	if (!next) {
		state->done = 1;
		return 1;
	}
	if (next < 64 + name_len || next > state->end - state->pos) {
		state->error = -TCPFS_EPROTO;
		return 1;
	}
	state->pos += next;
	return 0;

error:
	state->error = ret;
	return 1;
}

static __noinline int smb_query_directory_result(struct tcpfs_ctx *ctx)
{
	struct smb_dir_state state = { .ctx = ctx };
	__u32 length;
	__u16 structure_size, offset;
	int ret;

	ret = smb_rx_le16(ctx, 68, &structure_size);
	ret = ret ?: smb_rx_le16(ctx, 70, &offset);
	ret = ret ?: smb_rx_le32(ctx, 72, &length);
	if (ret || structure_size != 9 || offset < SMB2_HEADER_SIZE + 8 ||
	    4U + offset > ctx->rx_len || length > ctx->rx_len - 4U - offset)
		return -TCPFS_EPROTO;
	ctx->result.id = ctx->id;
	ctx->result.type = TCPFS_RESULT_DIRENT;
	ctx->result.payload_len = 0;
	state.pos = 4 + offset;
	state.end = state.pos + length;
	if (length)
		bpf_loop(SMB2_MAX_DIRENTS, smb_dirent_cb, &state, 0);
	return state.error;
}

static __always_inline int smb_read_result(struct tcpfs_ctx *ctx,
					   __u32 frame_length)
{
	__u32 available, data_len;
	__u16 structure_size;
	int data_offset;
	int ret;

	ret = smb_rx_le16(ctx, 68, &structure_size);
	data_offset = smb_rx_u8(ctx, 70);
	ret = ret ?: smb_rx_le32(ctx, 72, &data_len);
	if (ret || structure_size != 17 || data_offset < SMB2_HEADER_SIZE + 16 ||
	    4U + data_offset > frame_length ||
	    data_len > frame_length - 4U - data_offset || data_len > ctx->len)
		return -TCPFS_EPROTO;
	ctx->result.id = ctx->id;
	ctx->result.type = TCPFS_RESULT_DATA;
	ctx->result.rx_run.data_len = data_len;
	ctx->result.rx_run.wire_len = frame_length - 4U - data_offset;
	ctx->result.rx_run.rx_offset = 4U + data_offset;
	ctx->result.rx_run.flags = TCPFS_RX_RUN_F_FRAME_END;
	available = ctx->rx_len > 4U + data_offset ?
		ctx->rx_len - 4U - data_offset : 0;
	ctx->result.payload_len = available > data_len ? data_len : available;
	return 0;
}

SEC("struct_ops/build_request")
int BPF_PROG(datafs_smb_build_request,
	     struct tcpfs_build_request_ctx *tctx)
{
#define tctx (&tctx->output)
	int ret;

	if (!tctx->mount_arg_len || tctx->op < TCPFS_OP_LOOKUP ||
	    tctx->op > TCPFS_OP_READ ||
	    (tctx->op == TCPFS_OP_READ && !tctx->len))
		return -TCPFS_EINVAL;
	smb_build_negotiate(tctx);
	ret = tctx->payload_len ? 0 : -TCPFS_EINVAL;
	#undef tctx
	return ret;
}

SEC("struct_ops/frame_tx")
int BPF_PROG(datafs_smb_frame_tx, struct tcpfs_frame_tx_ctx *tctx)
{
#define tctx (&tctx->output)
	__u32 length;
	__u8 header[4];
	int ret;

	if (tctx->payload_len <= SMB2_NBSS_SIZE ||
	    tctx->payload_len - SMB2_NBSS_SIZE > 0xffffff)
		return -TCPFS_EINVAL;
	length = tctx->payload_len - SMB2_NBSS_SIZE;
	header[0] = 0;
	header[1] = length >> 16;
	header[2] = length >> 8;
	header[3] = length;
	ret = bpf_tcpfs_payload_write(tctx, 0, header, sizeof(header));
	#undef tctx
	return ret;
}

SEC("struct_ops/unframe_rx")
int BPF_PROG(datafs_smb_unframe_rx,
	     const struct tcpfs_unframe_rx_ctx *rx_ctx)
{
	__u32 frame_length, status;
	__u16 command;
	int ret;

	if (rx_ctx->len < 4)
		return 0;
	if (tcpfs_unframe_rx_read_byte(rx_ctx, 0) != 0)
		return -TCPFS_EPROTO;
	frame_length = (tcpfs_unframe_rx_read_byte(rx_ctx, 1) << 16) |
		       (tcpfs_unframe_rx_read_byte(rx_ctx, 2) << 8) |
		       tcpfs_unframe_rx_read_byte(rx_ctx, 3);
	frame_length += 4;
	if (frame_length < 4 + SMB2_HEADER_SIZE)
		return -TCPFS_EPROTO;
	if (rx_ctx->len < 4 + SMB2_HEADER_SIZE)
		return 0;
	ret = smb_unframe_rx_header(rx_ctx, &command, &status);
	if (ret)
		return ret;
	if (command == SMB2_READ && !status)
		return rx_ctx->len < 84 ? 0 : 4;
	if (frame_length > TCPFS_PAYLOAD_MAX)
		return -TCPFS_EPROTO;
	return rx_ctx->len < frame_length ? 0 : frame_length;
}

SEC("struct_ops/handle_response")
int BPF_PROG(datafs_smb_handle_response,
	     struct tcpfs_handle_response_ctx *tctx)
{
#define tctx (&tctx->output)
	__u64 message_id, request_id, session_id, file_persistent, file_volatile;
	__u32 status, tree_id, frame_length;
	__u16 command, dialect, request_command, security_mode, structure_size;
	int ret;

	ret = smb_check_header(tctx, &command, &status);
	ret = ret ?: smb_rx_le64(tctx, 28, &message_id);
	ret = ret ?: smb_rx_le32(tctx, 40, &tree_id);
	ret = ret ?: smb_rx_le64(tctx, 44, &session_id);
	ret = ret ?: smb_request_header(tctx, &request_command, &request_id);
	if (ret)
		return ret;
	if (command != request_command || message_id != request_id)
		return -TCPFS_EPROTO;
	frame_length = (smb_rx_u8(tctx, 1) << 16) |
		       (smb_rx_u8(tctx, 2) << 8) | smb_rx_u8(tctx, 3);
	frame_length += 4;

	SMB_LOG("datafs_smb: id=%llu cmd=%u status=%x", tctx->id,
		command, status);
	if (command == SMB2_SESSION_SETUP &&
	    status == SMB2_STATUS_MORE_PROCESSING_REQUIRED) {
		smb_build_session_setup(tctx, message_id + 1, session_id, 1);
		smb_continue(tctx);
		return 0;
	}
	if (status == SMB2_STATUS_NO_MORE_FILES &&
	    command == SMB2_QUERY_DIRECTORY) {
		tctx->result.id = tctx->id;
		tctx->result.type = TCPFS_RESULT_DIRENT;
		return 0;
	}
	if (status == SMB2_STATUS_END_OF_FILE && command == SMB2_READ) {
		tctx->result.id = tctx->id;
		tctx->result.type = TCPFS_RESULT_DATA;
		return 0;
	}
	if (status) {
		tctx->result.id = tctx->id;
		tctx->result.type = TCPFS_RESULT_ERROR;
		tctx->result.error = smb_status_errno(status);
		return 0;
	}

	switch (command) {
	case SMB2_NEGOTIATE:
		ret = smb_rx_le16(tctx, 68, &structure_size);
		ret = ret ?: smb_rx_le16(tctx, 70, &security_mode);
		ret = ret ?: smb_rx_le16(tctx, 72, &dialect);
		if (ret || structure_size != 65 || dialect != 0x0210)
			return -TCPFS_EPROTO;
		if (security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
			return -TCPFS_EOPNOTSUPP;
		smb_build_session_setup(tctx, message_id + 1, 0, 0);
		smb_continue(tctx);
		return 0;
	case SMB2_SESSION_SETUP:
		smb_build_tree_connect(tctx, message_id + 1, session_id);
		smb_continue(tctx);
		return 0;
	case SMB2_TREE_CONNECT:
		smb_build_create(tctx, message_id + 1, tree_id, session_id);
		smb_continue(tctx);
		return 0;
	case SMB2_CREATE:
		if (tctx->op != TCPFS_OP_READ && tctx->op != TCPFS_OP_READDIR)
			return smb_create_result(tctx);
		ret = smb_rx_le64(tctx, 132, &file_persistent);
		ret = ret ?: smb_rx_le64(tctx, 140, &file_volatile);
		if (ret)
			return ret;
		if (tctx->op == TCPFS_OP_READ)
			smb_build_read(tctx, message_id + 1, tree_id, session_id,
				       file_persistent, file_volatile);
		else
			smb_build_query_directory(tctx, message_id + 1, tree_id,
						  session_id, file_persistent,
						  file_volatile);
		smb_continue(tctx);
		return 0;
	case SMB2_READ:
		return smb_read_result(tctx, frame_length);
	case SMB2_QUERY_DIRECTORY:
		ret = smb_query_directory_result(tctx);
		break;
	default:
		ret = -TCPFS_EPROTO;
		break;
	}
	#undef tctx
	return ret;
}

SEC("struct_ops/recv_response")
int BPF_PROG(datafs_smb_recv_response,
	     struct tcpfs_recv_response_ctx *tctx)
{
#define tctx (&tctx->output)
	__u64 message_id;
	__u32 frame_length, status;
	__u16 command;

	if (tctx->rx_len < 4 + SMB2_HEADER_SIZE) {
		tctx->rx_need = 4 + SMB2_HEADER_SIZE;
		return -TCPFS_EAGAIN;
	}
	if (smb_rx_u8(tctx, 0) != 0)
		return -TCPFS_EPROTO;
	frame_length = (smb_rx_u8(tctx, 1) << 16) |
		       (smb_rx_u8(tctx, 2) << 8) | smb_rx_u8(tctx, 3);
	frame_length += 4;
	if (frame_length < 4 + SMB2_HEADER_SIZE ||
	    smb_rx_le32(tctx, 12, &status) ||
	    smb_rx_le16(tctx, 16, &command))
		return -TCPFS_EPROTO;
	if (frame_length > TCPFS_PAYLOAD_MAX) {
		if (command != SMB2_READ || status)
			return -TCPFS_EPROTO;
		if (tctx->rx_len < 84) {
			tctx->rx_need = 84;
			return -TCPFS_EAGAIN;
		}
	}
	if (smb_rx_le64(tctx, 28, &message_id))
		return -TCPFS_EPROTO;
	if (frame_length <= TCPFS_PAYLOAD_MAX && tctx->rx_len < frame_length) {
		tctx->rx_need = frame_length;
		return -TCPFS_EAGAIN;
	}
	tctx->result.id = message_id >> 4;
	tctx->frame_len = frame_length > TCPFS_PAYLOAD_MAX ? 4 : frame_length;
	#undef tctx
	return 0;
}

SEC(".struct_ops.link")
struct tcpfs_ops datafs_smb = {
	.name = "datafs_smb",
	.conn_style = TCPFS_CONN_NEW,
	.build_request = (void *)datafs_smb_build_request,
	.frame_tx = (void *)datafs_smb_frame_tx,
	.recv_response = (void *)datafs_smb_recv_response,
	.unframe_rx = (void *)datafs_smb_unframe_rx,
	.handle_response = (void *)datafs_smb_handle_response,
};

char _license[] SEC("license") = "GPL";
