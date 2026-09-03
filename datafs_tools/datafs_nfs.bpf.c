// SPDX-License-Identifier: GPL-2.0
/*
 * Read-only NFSv4.0 protocol implementation for datafs.
 *
 * Each request starts at the NFSv4 pseudo-filesystem root and resolves the
 * mount argument followed by the datafs path in one COMPOUND.  READ uses the
 * anonymous stateid, so no NFS open or client state is maintained.
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

#define NFS_RPC_LAST_FRAGMENT	BIT(31)
#define NFS_RPC_PROGRAM		100003
#define NFS_RPC_VERSION		2
#define NFS_RPC_CALL		0
#define NFS_RPC_REPLY		1
#define NFS_RPC_MSG_ACCEPTED	0
#define NFS_RPC_AUTH_NULL	0
#define NFS_RPC_AUTH_SYS		1
#define NFS_VERSION		4
#define NFS_COMPOUND_PROC	1

#define NFS_OP_GETATTR		9
#define NFS_OP_LOOKUP		15
#define NFS_OP_PUTROOTFH		24
#define NFS_OP_READ		25
#define NFS_OP_READDIR		26

#define NFS_FATTR_TYPE		BIT(1)
#define NFS_FATTR_SIZE		BIT(4)
#define NFS_FATTR_FILEID		BIT(20)
#define NFS_FATTR_MODE		BIT(1)

#define NFS_TYPE_REG		1
#define NFS_TYPE_DIR		2

#define NFS_MAX_COMPONENTS	64
#define NFS_MAX_READ		(1024U * 1024U)
#define NFS_READDIR_COUNT	2048
#define NFS_MAX_DIRENTS		128
#define NFS_MAX_REPLY		(NFS_MAX_READ + TCPFS_PAYLOAD_MAX)

#define TCPFS_EAGAIN		11
#define TCPFS_EINVAL		22
#define TCPFS_ENAMETOOLONG	36
#define TCPFS_EMSGSIZE		90
#define TCPFS_EOPNOTSUPP	95
#define TCPFS_EPROTO		71
#define TCPFS_EREMOTEIO		121

#ifdef TCPFS_NFS_DEBUG
#define NFS_LOG(...)		bpf_printk(__VA_ARGS__)
#else
#define NFS_LOG(...)		do { } while (0)
#endif

struct nfs_tx {
	struct tcpfs_ctx *ctx;
	__u32 pos;
	__s32 error;
};

static __always_inline void nfs_tx_u8(struct nfs_tx *tx, __u8 value)
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

static __always_inline void nfs_tx_u32(struct nfs_tx *tx, __u32 value)
{
	nfs_tx_u8(tx, value >> 24);
	nfs_tx_u8(tx, value >> 16);
	nfs_tx_u8(tx, value >> 8);
	nfs_tx_u8(tx, value);
}

static __always_inline void nfs_tx_u64(struct nfs_tx *tx, __u64 value)
{
	nfs_tx_u32(tx, value >> 32);
	nfs_tx_u32(tx, value);
}

static __always_inline void
nfs_tx_set_u32(struct nfs_tx *tx, __u32 offset, __u32 value)
{
	__u8 bytes[4] = {
		value >> 24,
		value >> 16,
		value >> 8,
		value,
	};
	int ret;

	if (tx->error)
		return;
	ret = bpf_tcpfs_payload_write(tx->ctx, offset, bytes, sizeof(bytes));
	if (ret)
		tx->error = ret;
}

static __always_inline void nfs_tx_machine_name(struct nfs_tx *tx)
{
	nfs_tx_u32(tx, 5);
	nfs_tx_u8(tx, 't');
	nfs_tx_u8(tx, 'c');
	nfs_tx_u8(tx, 'p');
	nfs_tx_u8(tx, 'f');
	nfs_tx_u8(tx, 's');
	nfs_tx_u8(tx, 0);
	nfs_tx_u8(tx, 0);
	nfs_tx_u8(tx, 0);
}

struct nfs_component_state {
	struct nfs_tx tx;
	__u32 source_len;
	__u32 length_offset;
	__u32 component_len;
	__u32 nops;
	__u32 active;
};

static __always_inline void
nfs_finish_component(struct nfs_component_state *state)
{
	__u32 pad;

	if (!state->active || state->tx.error)
		return;

	nfs_tx_set_u32(&state->tx, state->length_offset,
		       state->component_len);
	pad = (4 - (state->component_len & 3)) & 3;
	if (pad > 0)
		nfs_tx_u8(&state->tx, 0);
	if (pad > 1)
		nfs_tx_u8(&state->tx, 0);
	if (pad > 2)
		nfs_tx_u8(&state->tx, 0);
	state->active = 0;
}

static __always_inline long
nfs_component_char(struct nfs_component_state *state, __u32 index, char c)
{
	if (index >= state->source_len || !c) {
		nfs_finish_component(state);
		return 1;
	}

	if (c == '/') {
		nfs_finish_component(state);
		return state->tx.error ? 1 : 0;
	}

	if (!state->active) {
		if (state->nops >= NFS_MAX_COMPONENTS + 1) {
			state->tx.error = -TCPFS_ENAMETOOLONG;
			return 1;
		}
		nfs_tx_u32(&state->tx, NFS_OP_LOOKUP);
		state->length_offset = state->tx.pos;
		nfs_tx_u32(&state->tx, 0);
		state->component_len = 0;
		state->active = 1;
		state->nops++;
	}

	if (state->component_len == 255) {
		state->tx.error = -TCPFS_ENAMETOOLONG;
		return 1;
	}
	nfs_tx_u8(&state->tx, c);
	state->component_len++;
	return state->tx.error ? 1 : 0;
}

static long nfs_mount_component_cb(__u32 index, void *data)
{
	struct nfs_component_state *state = data;
	int value;

	if (index >= TCPFS_MOUNT_ARG_MAX)
		return 1;
	value = bpf_tcpfs_ctx_read_byte(state->tx.ctx,
					__builtin_offsetof(struct tcpfs_ctx,
							   mount_arg) + index);
	if (value < 0) {
		state->tx.error = value;
		return 1;
	}
	return nfs_component_char(state, index, value);
}

static long nfs_path_component_cb(__u32 index, void *data)
{
	struct nfs_component_state *state = data;
	int value;

	if (index >= TCPFS_PATH_MAX)
		return 1;
	value = bpf_tcpfs_ctx_read_byte(state->tx.ctx,
					__builtin_offsetof(struct tcpfs_ctx, path) +
					index);
	if (value < 0) {
		state->tx.error = value;
		return 1;
	}
	return nfs_component_char(state, index, value);
}

static __always_inline void
nfs_encode_rpc_header(struct nfs_tx *tx, __u32 xid)
{
	nfs_tx_u32(tx, 0); /* TCP record marker, completed by frame_tx. */
	nfs_tx_u32(tx, xid);
	nfs_tx_u32(tx, NFS_RPC_CALL);
	nfs_tx_u32(tx, NFS_RPC_VERSION);
	nfs_tx_u32(tx, NFS_RPC_PROGRAM);
	nfs_tx_u32(tx, NFS_VERSION);
	nfs_tx_u32(tx, NFS_COMPOUND_PROC);

	/* AUTH_SYS with uid/gid 0 and no supplementary groups. */
	nfs_tx_u32(tx, NFS_RPC_AUTH_SYS);
	nfs_tx_u32(tx, 28);
	nfs_tx_u32(tx, xid);
	nfs_tx_machine_name(tx);
	nfs_tx_u32(tx, 0);
	nfs_tx_u32(tx, 0);
	nfs_tx_u32(tx, 0);

	nfs_tx_u32(tx, NFS_RPC_AUTH_NULL);
	nfs_tx_u32(tx, 0);
}

static __always_inline void nfs_encode_getattr(struct nfs_tx *tx)
{
	nfs_tx_u32(tx, NFS_OP_GETATTR);
	nfs_tx_u32(tx, 2);
	nfs_tx_u32(tx, NFS_FATTR_TYPE | NFS_FATTR_SIZE | NFS_FATTR_FILEID);
	nfs_tx_u32(tx, NFS_FATTR_MODE);
}

static __always_inline void nfs_encode_readdir(struct nfs_tx *tx)
{
	nfs_tx_u32(tx, NFS_OP_READDIR);
	nfs_tx_u64(tx, 0); /* cookie */
	nfs_tx_u64(tx, 0); /* cookie verifier */
	nfs_tx_u32(tx, NFS_READDIR_COUNT);
	nfs_tx_u32(tx, NFS_READDIR_COUNT);
	nfs_tx_u32(tx, 1);
	nfs_tx_u32(tx, NFS_FATTR_TYPE);
}

static __always_inline void
nfs_encode_read(struct nfs_tx *tx, struct tcpfs_ctx *ctx)
{
	__u32 count = ctx->len > NFS_MAX_READ ? NFS_MAX_READ : ctx->len;

	nfs_tx_u32(tx, NFS_OP_READ);
	nfs_tx_u64(tx, 0); /* anonymous stateid */
	nfs_tx_u64(tx, 0);
	nfs_tx_u64(tx, ctx->offset);
	nfs_tx_u32(tx, count);
}

SEC("struct_ops/build_request")
int BPF_PROG(datafs_nfs_build_request,
	     struct tcpfs_build_request_ctx *tctx)
{
#define tctx (&tctx->output)
	struct nfs_component_state components = {};
	struct nfs_tx tx = {
		.ctx = tctx,
	};
	__u32 nops_offset;
	__u32 nops = 1;

	if (tctx->op < TCPFS_OP_LOOKUP || tctx->op > TCPFS_OP_READ)
		return -TCPFS_EOPNOTSUPP;
	if (tctx->op == TCPFS_OP_READ && !tctx->len)
		return -TCPFS_EINVAL;
	tctx->payload_len = 0;

	NFS_LOG("datafs_nfs: build id=%llu op=%u path_len=%u",
		tctx->id, tctx->op, tctx->path_len);
	nfs_encode_rpc_header(&tx, tctx->id);

	nfs_tx_u32(&tx, 0); /* empty COMPOUND tag */
	nfs_tx_u32(&tx, 0); /* NFSv4.0 minor version */
	nops_offset = tx.pos;
	nfs_tx_u32(&tx, 0);
	nfs_tx_u32(&tx, NFS_OP_PUTROOTFH);

	components.tx = tx;
	components.source_len = tctx->mount_arg_len;
	components.nops = nops;
	bpf_loop(TCPFS_MOUNT_ARG_MAX, nfs_mount_component_cb, &components, 0);
	nfs_finish_component(&components);

	components.source_len = tctx->path_len;
	components.active = 0;
	components.component_len = 0;
	bpf_loop(TCPFS_PATH_MAX, nfs_path_component_cb, &components, 0);
	nfs_finish_component(&components);
	tx = components.tx;
	nops = components.nops;

	if (tctx->op == TCPFS_OP_READ)
		nfs_encode_read(&tx, tctx);
	else if (tctx->op == TCPFS_OP_READDIR)
		nfs_encode_readdir(&tx);
	else
		nfs_encode_getattr(&tx);
	nops++;
	nfs_tx_set_u32(&tx, nops_offset, nops);
	if (tx.error)
		return tx.error;

	tctx->payload_len = tx.pos;
	NFS_LOG("datafs_nfs: built id=%llu nops=%u bytes=%u",
		tctx->id, nops, tctx->payload_len);
	#undef tctx
	return 0;
}

SEC("struct_ops/frame_tx")
int BPF_PROG(datafs_nfs_frame_tx, struct tcpfs_frame_tx_ctx *tctx)
{
#define tctx (&tctx->output)
	struct nfs_tx tx = {
		.ctx = tctx,
	};

	if (tctx->payload_len <= 4)
		return -TCPFS_EINVAL;
	nfs_tx_set_u32(&tx, 0,
		       NFS_RPC_LAST_FRAGMENT | (tctx->payload_len - 4));
	#undef tctx
	return tx.error;
}

struct nfs_rx {
	struct tcpfs_ctx *ctx;
	__u32 pos;
	__u32 limit;
};

static __noinline int nfs_rx_u32(struct nfs_rx *rx, __u32 *value)
{
	__u32 pos = rx->pos;
	__u32 offset;
	__s64 raw;

	if (pos > rx->limit || rx->limit - pos < sizeof(*value))
		return -TCPFS_EAGAIN;
	offset = __builtin_offsetof(struct tcpfs_ctx, rx) + pos;
	raw = bpf_tcpfs_ctx_read_be32(rx->ctx, offset);
	if (raw < 0)
		return -TCPFS_EPROTO;
	*value = (__u32)raw;
	rx->pos = pos + sizeof(*value);
	return 0;
}

static __noinline int nfs_rx_u64(struct nfs_rx *rx, __u64 *value)
{
	__u32 high, low;
	int ret;

	ret = nfs_rx_u32(rx, &high);
	if (ret)
		return ret;
	ret = nfs_rx_u32(rx, &low);
	if (ret)
		return ret;
	*value = ((__u64)high << 32) | low;
	return 0;
}

static __always_inline int nfs_rx_skip(struct nfs_rx *rx, __u32 len)
{
	if (rx->pos > rx->limit || len > rx->limit - rx->pos)
		return -TCPFS_EAGAIN;
	rx->pos += len;
	return 0;
}

static __noinline int
nfs_rx_opaque(struct nfs_rx *rx, __u32 *offset, __u32 *len)
{
	__u32 padded;
	int ret;

	ret = nfs_rx_u32(rx, len);
	if (ret)
		return ret;
	if (*len > TCPFS_PAYLOAD_MAX)
		return -TCPFS_EMSGSIZE;
	padded = (*len + 3) & ~3U;
	if (padded < *len)
		return -TCPFS_EPROTO;
	*offset = rx->pos;
	return nfs_rx_skip(rx, padded);
}

static __always_inline int
nfs_record_length(struct tcpfs_ctx *ctx, __u32 *total)
{
	__u32 marker;

	if (ctx->rx_len < 4)
		return -TCPFS_EAGAIN;
	marker = ((__u32)ctx->rx[0] << 24) | ((__u32)ctx->rx[1] << 16) |
		 ((__u32)ctx->rx[2] << 8) | ctx->rx[3];
	if (!(marker & NFS_RPC_LAST_FRAGMENT))
		return -TCPFS_EOPNOTSUPP;
	marker &= ~NFS_RPC_LAST_FRAGMENT;
	if (marker > NFS_MAX_REPLY || marker < 24)
		return -TCPFS_EPROTO;
	*total = marker + 4;
	return 0;
}

static __always_inline int
nfs_unframe_rx(const struct tcpfs_unframe_rx_ctx *ctx)
{
	int byte0, byte1, byte2, byte3;
	__u32 marker;

	if (ctx->len < 4)
		return 0;
	byte0 = tcpfs_unframe_rx_read_byte(ctx, 0);
	byte1 = tcpfs_unframe_rx_read_byte(ctx, 1);
	byte2 = tcpfs_unframe_rx_read_byte(ctx, 2);
	byte3 = tcpfs_unframe_rx_read_byte(ctx, 3);
	if (byte0 < 0 || byte1 < 0 || byte2 < 0 || byte3 < 0)
		return -TCPFS_EPROTO;
	marker = ((__u32)byte0 << 24) | ((__u32)byte1 << 16) |
		 ((__u32)byte2 << 8) | byte3;
	if (!(marker & NFS_RPC_LAST_FRAGMENT))
		return -TCPFS_EOPNOTSUPP;
	marker &= ~NFS_RPC_LAST_FRAGMENT;
	if (marker > NFS_MAX_REPLY || marker < 24)
		return -TCPFS_EPROTO;
	return 4;
}

static __noinline int nfs_status_to_errno(__u32 status)
{
	switch (status) {
	case 0:
	case 1:
	case 2:
	case 5:
	case 6:
	case 13:
	case 17:
	case 18:
	case 20:
	case 21:
	case 22:
	case 27:
	case 28:
	case 30:
		return -status;
	case 63:
		return -TCPFS_ENAMETOOLONG;
	case 66:
		return -39;
	case 70:
		return -116;
	case 10004:
		return -TCPFS_EOPNOTSUPP;
	case 10008:
		return -TCPFS_EAGAIN;
	default:
		return -TCPFS_EREMOTEIO;
	}
}

struct nfs_attributes {
	__u64 size;
	__u64 fileid;
	__u32 type;
	__u32 mode;
	__u32 present;
};

#define NFS_ATTR_PRESENT_TYPE	BIT(0)
#define NFS_ATTR_PRESENT_SIZE	BIT(1)
#define NFS_ATTR_PRESENT_FILEID	BIT(2)
#define NFS_ATTR_PRESENT_MODE	BIT(3)

static __noinline int
nfs_parse_attributes(struct nfs_rx *rx, struct nfs_attributes *attrs,
		     __u32 allowed0, __u32 allowed1)
{
	__u32 bitmap0 = 0, bitmap1 = 0, bitmap2 = 0;
	__u32 words, attr_len, attr_end, padded_end;
	int ret;

	ret = nfs_rx_u32(rx, &words);
	if (ret)
		return ret;
	if (words > 3)
		return -TCPFS_EPROTO;
	if (words > 0) {
		ret = nfs_rx_u32(rx, &bitmap0);
		if (ret)
			return ret;
	}
	if (words > 1) {
		ret = nfs_rx_u32(rx, &bitmap1);
		if (ret)
			return ret;
	}
	if (words > 2) {
		ret = nfs_rx_u32(rx, &bitmap2);
		if (ret)
			return ret;
	}
	if ((bitmap0 & ~allowed0) || (bitmap1 & ~allowed1) || bitmap2)
		return -TCPFS_EPROTO;

	ret = nfs_rx_u32(rx, &attr_len);
	if (ret)
		return ret;
	if (rx->pos > rx->limit || attr_len > rx->limit - rx->pos)
		return -TCPFS_EAGAIN;
	attr_end = rx->pos + attr_len;
	padded_end = rx->pos + ((attr_len + 3) & ~3U);
	if (padded_end < attr_end || padded_end > rx->limit)
		return -TCPFS_EAGAIN;

	if (bitmap0 & NFS_FATTR_TYPE) {
		ret = nfs_rx_u32(rx, &attrs->type);
		if (ret)
			return ret;
		attrs->present |= NFS_ATTR_PRESENT_TYPE;
	}
	if (bitmap0 & NFS_FATTR_SIZE) {
		ret = nfs_rx_u64(rx, &attrs->size);
		if (ret)
			return ret;
		attrs->present |= NFS_ATTR_PRESENT_SIZE;
	}
	if (bitmap0 & NFS_FATTR_FILEID) {
		ret = nfs_rx_u64(rx, &attrs->fileid);
		if (ret)
			return ret;
		attrs->present |= NFS_ATTR_PRESENT_FILEID;
	}
	if (bitmap1 & NFS_FATTR_MODE) {
		ret = nfs_rx_u32(rx, &attrs->mode);
		if (ret)
			return ret;
		attrs->present |= NFS_ATTR_PRESENT_MODE;
	}
	if (rx->pos != attr_end)
		return -TCPFS_EPROTO;
	rx->pos = padded_end;
	return 0;
}

static __always_inline int nfs_result_putc(struct tcpfs_ctx *ctx, char c)
{
	return bpf_tcpfs_result_append(ctx, &c, sizeof(c));
}

static __noinline int nfs_parse_getattr(struct nfs_rx *rx)
{
	struct tcpfs_ctx *ctx = rx->ctx;
	struct nfs_attributes attrs = {};
	__u32 permissions;
	int ret;

	ret = nfs_parse_attributes(rx, &attrs,
				   NFS_FATTR_TYPE | NFS_FATTR_SIZE |
				   NFS_FATTR_FILEID, NFS_FATTR_MODE);
	if (ret)
		return ret;
	if (!(attrs.present & NFS_ATTR_PRESENT_TYPE))
		return -TCPFS_EPROTO;

	if (attrs.type == NFS_TYPE_REG) {
		permissions = attrs.present & NFS_ATTR_PRESENT_MODE ?
			attrs.mode & 0555 : 0444;
		ctx->result.mode = 0100000 | permissions;
	} else if (attrs.type == NFS_TYPE_DIR) {
		permissions = attrs.present & NFS_ATTR_PRESENT_MODE ?
			attrs.mode & 0555 : 0555;
		ctx->result.mode = 0040000 | permissions;
	} else {
		return -TCPFS_EOPNOTSUPP;
	}

	ctx->result.type = TCPFS_RESULT_ATTR;
	if (attrs.present & NFS_ATTR_PRESENT_SIZE)
		ctx->result.flags |= TCPFS_RESULT_F_SIZE_VALID;
	ctx->result.ino = attrs.present & NFS_ATTR_PRESENT_FILEID ?
		attrs.fileid : (ctx->ino ? ctx->ino : ctx->id + 1);
	ctx->result.size = attrs.present & NFS_ATTR_PRESENT_SIZE ? attrs.size : 0;
	return 0;
}

struct nfs_readdir_state {
	struct nfs_rx rx;
	__s32 error;
	__u32 done;
};

static long nfs_readdir_entry_cb(__u32 i, void *data)
{
	struct nfs_readdir_state *state = data;
	struct nfs_rx *rx = &state->rx;
	struct tcpfs_ctx *ctx = rx->ctx;
	struct nfs_attributes attrs = {};
	__u64 ignored64;
	__u32 present, ignored32, name_offset, name_len;
	int ret;

	if (i >= NFS_MAX_DIRENTS || state->error || state->done)
		return 1;
	ret = nfs_rx_u32(rx, &present);
	if (ret)
		goto error;
	if (!present) {
		ret = nfs_rx_u32(rx, &ignored32); /* eof */
		if (ret)
			goto error;
		if (ignored32 > 1) {
			ret = -TCPFS_EPROTO;
			goto error;
		}
		state->done = 1;
		return 1;
	}
	if (present != 1) {
		ret = -TCPFS_EPROTO;
		goto error;
	}
	ret = nfs_rx_u64(rx, &ignored64); /* cookie */
	if (ret)
		goto error;
	ret = nfs_rx_opaque(rx, &name_offset, &name_len);
	if (ret)
		goto error;
	if (!name_len || name_len > 255) {
		ret = -TCPFS_EPROTO;
		goto error;
	}
	ret = nfs_parse_attributes(rx, &attrs, NFS_FATTR_TYPE, 0);
	if (ret)
		goto error;
	if (!(attrs.present & NFS_ATTR_PRESENT_TYPE)) {
		ret = -TCPFS_EPROTO;
		goto error;
	}
	if (ctx->result.payload_len + name_len + 2 > TCPFS_PAYLOAD_MAX) {
		state->done = 1;
		return 1;
	}
	ret = bpf_tcpfs_result_append_rx(ctx, name_offset, name_len);
	if (ret)
		goto error;
	if (attrs.type == NFS_TYPE_DIR) {
		ret = nfs_result_putc(ctx, '/');
		if (ret)
			goto error;
	}
	ret = nfs_result_putc(ctx, '\n');
	if (ret)
		goto error;
	return 0;

error:
	state->error = ret;
	return 1;
}

static __noinline int nfs_parse_readdir(struct nfs_rx *rx)
{
	struct nfs_readdir_state state = {
		.rx = *rx,
	};
	struct tcpfs_ctx *ctx = rx->ctx;
	__u64 ignored64;
	int ret;

	ret = nfs_rx_u64(&state.rx, &ignored64); /* cookie verifier */
	if (ret)
		return ret;
	ctx->result.type = TCPFS_RESULT_DIRENT;
	ctx->result.payload_len = 0;
	bpf_loop(NFS_MAX_DIRENTS, nfs_readdir_entry_cb, &state, 0);
	*rx = state.rx;
	return state.error;
}

static __noinline int nfs_parse_read(struct nfs_rx *rx, __u32 total)
{
	struct tcpfs_ctx *ctx = rx->ctx;
	__u32 eof, data_len, padded_len, available;
	int ret;

	ret = nfs_rx_u32(rx, &eof);
	if (ret)
		return ret;
	if (eof > 1)
		return -TCPFS_EPROTO;
	ret = nfs_rx_u32(rx, &data_len);
	if (ret)
		return ret;
	if (data_len > NFS_MAX_READ || data_len > ctx->len)
		return -TCPFS_EPROTO;
	padded_len = (data_len + 3) & ~3U;
	if (padded_len < data_len || rx->pos > total || padded_len > total - rx->pos)
		return -TCPFS_EPROTO;

	available = rx->limit > rx->pos ? rx->limit - rx->pos : 0;
	if (available > data_len)
		available = data_len;
	ctx->result.type = TCPFS_RESULT_DATA;
	ctx->result.flags = TCPFS_RESULT_F_SIZE_VALID;
	ctx->result.offset = ctx->offset;
	ctx->result.size = data_len;
	ctx->result.rx_run.data_len = data_len;
	ctx->result.rx_run.wire_len = padded_len;
	ctx->result.rx_run.rx_offset = rx->pos;
	ctx->result.rx_run.flags = TCPFS_RX_RUN_F_FRAME_END;
	ctx->result.payload_len = available;
	return 0;
}

static __noinline int
nfs_parse_reply_header(struct nfs_rx *rx, __u32 *compound_status,
		       __u32 *nresults)
{
	struct tcpfs_ctx *ctx = rx->ctx;
	__u32 value, verifier_len, ignored_offset, ignored_len;
	int ret;

	ret = nfs_rx_skip(rx, 4); /* record marker */
	ret = ret ?: nfs_rx_u32(rx, &value);
	if (ret)
		return ret;
	if (value != (__u32)ctx->id)
		return -TCPFS_EPROTO;
	ret = nfs_rx_u32(rx, &value);
	if (ret || value != NFS_RPC_REPLY)
		return ret ?: -TCPFS_EPROTO;
	ret = nfs_rx_u32(rx, &value);
	if (ret || value != NFS_RPC_MSG_ACCEPTED)
		return ret ?: -13;

	ret = nfs_rx_u32(rx, &value); /* verifier flavor */
	ret = ret ?: nfs_rx_u32(rx, &verifier_len);
	if (ret)
		return ret;
	if (verifier_len > 400)
		return -TCPFS_EPROTO;
	ret = nfs_rx_skip(rx, (verifier_len + 3) & ~3U);
	ret = ret ?: nfs_rx_u32(rx, &value); /* accepted status */
	if (ret)
		return ret;
	if (value)
		return value == 3 ? -TCPFS_EOPNOTSUPP : -TCPFS_EPROTO;

	ret = nfs_rx_u32(rx, compound_status);
	if (ret)
		return ret;
	ret = nfs_rx_opaque(rx, &ignored_offset, &ignored_len); /* tag */
	if (ret)
		return ret;
	ret = nfs_rx_u32(rx, nresults);
	if (ret)
		return ret;
	if (*nresults > NFS_MAX_COMPONENTS + 2)
		return -TCPFS_EPROTO;
	return 0;
}

struct nfs_response_state {
	struct nfs_rx rx;
	__u32 total;
	__u32 nresults;
	__s32 error;
	__u32 done;
};

static long nfs_result_cb(__u32 i, void *data)
{
	struct nfs_response_state *state = data;
	struct tcpfs_ctx *ctx = state->rx.ctx;
	__u32 op, status;
	int ret;

	if (i >= state->nresults || state->error || state->done)
		return 1;
	ret = nfs_rx_u32(&state->rx, &op);
	ret = ret ?: nfs_rx_u32(&state->rx, &status);
	if (ret)
		goto error;
	if (status) {
		ctx->result.type = TCPFS_RESULT_ERROR;
		ctx->result.error = nfs_status_to_errno(status);
		state->done = 1;
		return 1;
	}

	switch (op) {
	case NFS_OP_PUTROOTFH:
	case NFS_OP_LOOKUP:
		if (i + 1 >= state->nresults)
			goto protocol_error;
		return 0;
	case NFS_OP_GETATTR:
		if (ctx->op != TCPFS_OP_LOOKUP && ctx->op != TCPFS_OP_GETATTR)
			goto protocol_error;
		ret = nfs_parse_getattr(&state->rx);
		break;
	case NFS_OP_READDIR:
		if (ctx->op != TCPFS_OP_READDIR)
			goto protocol_error;
		ret = nfs_parse_readdir(&state->rx);
		break;
	case NFS_OP_READ:
		if (ctx->op != TCPFS_OP_READ)
			goto protocol_error;
		ret = nfs_parse_read(&state->rx, state->total);
		break;
	default:
		goto protocol_error;
	}
	if (i + 1 != state->nresults && !ret)
		ret = -TCPFS_EPROTO;
	state->error = ret;
	state->done = 1;
	return 1;

protocol_error:
	ret = -TCPFS_EPROTO;
error:
	state->error = ret;
	return 1;
}

SEC("struct_ops/unframe_rx")
int BPF_PROG(datafs_nfs_unframe_rx,
	     const struct tcpfs_unframe_rx_ctx *rx_ctx)
{
	return nfs_unframe_rx(rx_ctx);
}

SEC("struct_ops/handle_response")
int BPF_PROG(datafs_nfs_handle_response,
	     struct tcpfs_handle_response_ctx *tctx)
{
#define tctx (&tctx->output)
	struct nfs_response_state state = {
		.rx = {
			.ctx = tctx,
			.limit = tctx->rx_len,
		},
	};
	__u32 compound_status, nresults, total;
	int ret;

	ret = nfs_record_length(tctx, &total);
	if (ret) {
		if (ret == -TCPFS_EAGAIN)
			tctx->rx_need = 4;
		return ret;
	}
	if (tctx->op != TCPFS_OP_READ && total > tctx->rx_len) {
		tctx->rx_need = total;
		return -TCPFS_EAGAIN;
	}

	tctx->result.id = tctx->id;
	tctx->result.error = 0;
	tctx->result.type = TCPFS_RESULT_NONE;
	tctx->result.flags = 0;
	tctx->result.payload_len = 0;
	ret = nfs_parse_reply_header(&state.rx, &compound_status, &nresults);
	if (ret)
		return ret;
	state.total = total;
	state.nresults = nresults;
	bpf_loop(NFS_MAX_COMPONENTS + 2, nfs_result_cb, &state, 0);
	ret = state.error;
	if (!ret && !state.done && compound_status) {
		tctx->result.type = TCPFS_RESULT_ERROR;
		tctx->result.error = nfs_status_to_errno(compound_status);
		state.done = 1;
	}
	if (!ret && !state.done)
		ret = -TCPFS_EPROTO;
	if (ret == -TCPFS_EAGAIN && total <= tctx->rx_len)
		ret = -TCPFS_EPROTO;
	if (ret == -TCPFS_EAGAIN) {
		tctx->rx_need = state.rx.pos + 64;
		if (tctx->rx_need > TCPFS_PAYLOAD_MAX)
			tctx->rx_need = TCPFS_PAYLOAD_MAX;
		if (tctx->rx_need <= tctx->rx_len)
			ret = -TCPFS_EMSGSIZE;
	}
#ifdef TCPFS_TEST_OVERSIZED_RESULT
	if (!ret)
		tctx->result.payload_len = TCPFS_PAYLOAD_MAX + 1;
#endif
	NFS_LOG("datafs_nfs: reply id=%llu op=%u type=%u err=%d bytes=%u",
		tctx->id, tctx->op, tctx->result.type, ret,
		tctx->result.payload_len);
	#undef tctx
	return ret;
}

SEC("struct_ops/recv_response")
int BPF_PROG(datafs_nfs_recv_response,
	     struct tcpfs_recv_response_ctx *tctx)
{
#define tctx (&tctx->output)
	__s64 xid;

	if (tctx->rx_len < 8) {
		tctx->rx_need = 8;
		return -TCPFS_EAGAIN;
	}
	xid = bpf_tcpfs_ctx_read_be32(tctx,
			      __builtin_offsetof(struct tcpfs_ctx, rx) + 4);
	if (xid < 0)
		return -TCPFS_EPROTO;
	tctx->result.id = (__u32)xid;
	tctx->frame_len = 4;
	#undef tctx
	return 0;
}

SEC(".struct_ops.link")
#if defined(TCPFS_TEST_OVERSIZED_RESULT)
#define TCPFS_NFS_OPS datafs_nfs_bad
#define TCPFS_NFS_OPS_NAME "datafs_nfs_bad"
#define TCPFS_NFS_CONN_STYLE TCPFS_CONN_NEW
#elif defined(TCPFS_TEST_CONN_OVERLAP)
#define TCPFS_NFS_OPS datafs_nfs_ovl
#define TCPFS_NFS_OPS_NAME "datafs_nfs_ovl"
#define TCPFS_NFS_CONN_STYLE TCPFS_CONN_OVERLAP
#elif defined(TCPFS_TEST_CONN_SERIAL)
#define TCPFS_NFS_OPS datafs_nfs_serial
#define TCPFS_NFS_OPS_NAME "datafs_nfs_serial"
#define TCPFS_NFS_CONN_STYLE TCPFS_CONN_SERIAL
#else
#define TCPFS_NFS_OPS datafs_nfs
#define TCPFS_NFS_OPS_NAME "datafs_nfs"
#define TCPFS_NFS_CONN_STYLE TCPFS_CONN_NEW
#endif
struct tcpfs_ops TCPFS_NFS_OPS = {
	.name = TCPFS_NFS_OPS_NAME,
	.conn_style = TCPFS_NFS_CONN_STYLE,
	.build_request = (void *)datafs_nfs_build_request,
	.frame_tx = (void *)datafs_nfs_frame_tx,
	.recv_response = (void *)datafs_nfs_recv_response,
	.unframe_rx = (void *)datafs_nfs_unframe_rx,
	.handle_response = (void *)datafs_nfs_handle_response,
};

char _license[] SEC("license") = "GPL";
