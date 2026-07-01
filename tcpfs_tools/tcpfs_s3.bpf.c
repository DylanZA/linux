// SPDX-License-Identifier: GPL-2.0
/*
 * Sample tcpfs BPF app that emits plaintext HTTP/1.1 requests compatible with
 * S3-style object stores. It is intentionally suitable for loopback tests or a
 * trusted plaintext proxy, not direct AWS S3 HTTPS/SigV4 access.
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

#define TCPFS_NAME_LEN		32
#define TCPFS_BUCKET_MAX	128
#define TCPFS_PATH_MAX		512
#define TCPFS_PAYLOAD_MAX	4096
#define NO_UNROLL		_Pragma("clang loop unroll(disable)")
#define S3_BUCKET_MAX		32
#define S3_PATH_MAX		32
#define S3_SCAN_MAX		1024

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

struct tcpfs_result {
	__u64 id;
	__u64 ino;
	__u64 size;
	__u64 offset;
	__u32 mode;
	__s32 error;
	__u32 type;
	__u32 payload_len;
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
	__u32 bucket_len;
	char path[TCPFS_PATH_MAX];
	char bucket[TCPFS_BUCKET_MAX];
	__u8 payload[TCPFS_PAYLOAD_MAX];
	__u8 rx[TCPFS_PAYLOAD_MAX];
	struct tcpfs_result result;
};

struct tcpfs_ops {
	char name[TCPFS_NAME_LEN];
	int (*build_request)(struct tcpfs_ctx *ctx);
	int (*frame_tx)(struct tcpfs_ctx *ctx);
	int (*unframe_rx)(struct tcpfs_ctx *ctx);
	int (*handle_response)(struct tcpfs_ctx *ctx);
	int (*on_unsolicited)(struct tcpfs_ctx *ctx);
};

static __always_inline int putc(struct tcpfs_ctx *ctx, int *pos, char c)
{
	if (*pos >= TCPFS_PAYLOAD_MAX)
		return -1;
	ctx->payload[*pos] = c;
	*pos += 1;
	return 0;
}

struct append_state {
	struct tcpfs_ctx *ctx;
	const char *src;
	__u32 pos;
	__u32 len;
	__s32 err;
};

static long append_lit_cb(__u32 i, void *data)
{
	struct append_state *st = data;

	if (i >= 40)
		return 1;
	if (i >= st->len)
		return 1;
	if (st->pos >= TCPFS_PAYLOAD_MAX) {
		st->err = -1;
		return 1;
	}
	st->ctx->payload[st->pos++] = st->src[i];
	return 0;
}

static long append_bucket_cb(__u32 i, void *data)
{
	struct append_state *st = data;
	char c;

	if (i >= st->ctx->bucket_len)
		return 1;
	c = st->ctx->bucket[i];
	if (!c)
		return 1;
	if (st->pos >= TCPFS_PAYLOAD_MAX) {
		st->err = -1;
		return 1;
	}
	st->ctx->payload[st->pos++] = c;
	return 0;
}

static long append_path_cb(__u32 i, void *data)
{
	struct append_state *st = data;
	char c;

	if (i >= st->ctx->path_len)
		return 1;
	c = st->ctx->path[i];
	if (!c)
		return 1;
	if (st->pos >= TCPFS_PAYLOAD_MAX) {
		st->err = -1;
		return 1;
	}
	st->ctx->payload[st->pos++] = c;
	return 0;
}

static __always_inline int puts_lit(struct tcpfs_ctx *ctx, int *pos,
				    const char *s, int len)
{
	struct append_state st = {
		.ctx = ctx,
		.src = s,
		.pos = *pos,
		.len = len,
	};

	bpf_loop(len, append_lit_cb, &st, 0);
	*pos = st.pos;
	return st.err;
}

#define PUTS(ctx, pos, literal) \
	puts_lit((ctx), (pos), (literal), sizeof(literal) - 1)

static __always_inline int put_bucket_path(struct tcpfs_ctx *ctx, int *pos)
{
	struct append_state st = {
		.ctx = ctx,
		.pos = *pos,
	};

	if (putc(ctx, pos, '/'))
		return -1;
	st.pos = *pos;
	bpf_loop(S3_BUCKET_MAX, append_bucket_cb, &st, 0);
	*pos = st.pos;
	if (st.err)
		return st.err;
	if (ctx->path_len) {
		if (putc(ctx, pos, '/'))
			return -1;
		st.pos = *pos;
		st.err = 0;
		bpf_loop(S3_PATH_MAX, append_path_cb, &st, 0);
		*pos = st.pos;
		if (st.err)
			return st.err;
	}
	return 0;
}

static __always_inline int put_u64(struct tcpfs_ctx *ctx, int *pos, __u64 val)
{
	char tmp[20];
	int i, n = 0;

	if (!val)
		return putc(ctx, pos, '0');
	NO_UNROLL
	for (i = 0; i < 20; i++) {
		if (!val)
			break;
		tmp[n++] = '0' + val % 10;
		val /= 10;
	}
	NO_UNROLL
	for (i = 19; i >= 0; i--) {
		if (i >= n)
			continue;
		if (putc(ctx, pos, tmp[i]))
			return -1;
	}
	return 0;
}

SEC("struct_ops/build_request")
int BPF_PROG(tcpfs_s3_build_request, struct tcpfs_ctx *tctx)
{
#define ctx tctx
	bpf_printk("tcpfs_s3: build_request id=%llu op=%u path_len=%u",
		   ctx->id, ctx->op, ctx->path_len);

	if (!ctx->bucket_len)
		return -22;

	if (ctx->op == TCPFS_OP_READ) {
		__builtin_memcpy(ctx->payload,
				 "GET /tcpfs HTTP/1.1\r\nRange: bytes=0-4095\r\nHost: tcpfs-s3\r\nConnection: close\r\n\r\n",
				 83);
		ctx->payload_len = 83;
		bpf_printk("tcpfs_s3: built read id=%llu payload_len=%u",
			   ctx->id, ctx->payload_len);
		return 0;
	} else if (ctx->op == TCPFS_OP_READDIR) {
		__builtin_memcpy(ctx->payload,
				 "GET /tcpfs?list-type=2&delimiter=/ HTTP/1.1\r\nHost: tcpfs-s3\r\nConnection: close\r\n\r\n",
				 86);
		ctx->payload_len = 86;
		bpf_printk("tcpfs_s3: built readdir id=%llu payload_len=%u",
			   ctx->id, ctx->payload_len);
		return 0;
	} else {
		__builtin_memcpy(ctx->payload,
				 "HEAD /tcpfs HTTP/1.1\r\nHost: tcpfs-s3\r\nConnection: close\r\n\r\n",
				 65);
		ctx->payload_len = 65;
		bpf_printk("tcpfs_s3: built attr id=%llu payload_len=%u",
			   ctx->id, ctx->payload_len);
		return 0;
	}
#undef ctx
}

SEC("struct_ops/frame_tx")
int BPF_PROG(tcpfs_s3_frame_tx, struct tcpfs_ctx *tctx)
{
#define ctx tctx
	bpf_printk("tcpfs_s3: frame_tx id=%llu payload_len=%u",
		   ctx->id, ctx->payload_len);
	return ctx->payload_len ? 0 : -22;
#undef ctx
}

static __always_inline int starts_status(struct tcpfs_ctx *ctx, char a, char b,
					 char c)
{
	return ctx->rx_len >= 12 && ctx->rx[9] == a && ctx->rx[10] == b &&
	       ctx->rx[11] == c;
}

static __always_inline int find_body(struct tcpfs_ctx *ctx)
{
	int i;

	NO_UNROLL
	for (i = 0; i < S3_SCAN_MAX - 3; i++) {
		if (i + 4 > ctx->rx_len)
			break;
		if (ctx->rx[i] == '\r' && ctx->rx[i + 1] == '\n' &&
		    ctx->rx[i + 2] == '\r' && ctx->rx[i + 3] == '\n')
			return i + 4;
	}
	return -1;
}

static __always_inline __u64 parse_content_length(struct tcpfs_ctx *ctx)
{
	__u64 len = 0;
	int i, j;

	NO_UNROLL
	for (i = 0; i < S3_SCAN_MAX - 15; i++) {
		if (i + 15 >= ctx->rx_len)
			break;
		if (ctx->rx[i] != 'C' || ctx->rx[i + 1] != 'o' ||
		    ctx->rx[i + 2] != 'n' || ctx->rx[i + 3] != 't' ||
		    ctx->rx[i + 4] != 'e' || ctx->rx[i + 5] != 'n' ||
		    ctx->rx[i + 6] != 't' || ctx->rx[i + 7] != '-' ||
		    ctx->rx[i + 8] != 'L' || ctx->rx[i + 9] != 'e' ||
		    ctx->rx[i + 10] != 'n' || ctx->rx[i + 11] != 'g' ||
		    ctx->rx[i + 12] != 't' || ctx->rx[i + 13] != 'h' ||
		    ctx->rx[i + 14] != ':')
			continue;
		i += 15;
		NO_UNROLL
		for (j = 0; j < 20; j++) {
			char c;

			if (i + j >= ctx->rx_len)
				break;
			c = ctx->rx[i + j];
			if (c == ' ')
				continue;
			if (c < '0' || c > '9')
				break;
			len = len * 10 + c - '0';
		}
		break;
	}
	return len;
}

SEC("struct_ops/unframe_rx")
int BPF_PROG(tcpfs_s3_unframe_rx, struct tcpfs_ctx *tctx)
{
#define ctx tctx
	ctx->frame_len = ctx->rx_len;
	bpf_printk("tcpfs_s3: unframe_rx id=%llu rx_len=%u",
		   ctx->id, ctx->rx_len);
	return 0;
#undef ctx
}

SEC("struct_ops/handle_response")
int BPF_PROG(tcpfs_s3_handle_response, struct tcpfs_ctx *tctx)
{
#define ctx tctx
	bpf_printk("tcpfs_s3: handle_response id=%llu op=%u rx_len=%u",
		   ctx->id, ctx->op, ctx->rx_len);

	ctx->result.id = ctx->id;
	ctx->result.error = 0;

	if (ctx->op == TCPFS_OP_READ) {
		ctx->result.type = TCPFS_RESULT_DATA;
		ctx->result.payload_len = 0;
		bpf_printk("tcpfs_s3: result read id=%llu payload_len=%u",
			   ctx->id, ctx->result.payload_len);
		return 0;
	}

	if (ctx->op == TCPFS_OP_READDIR) {
		ctx->result.type = TCPFS_RESULT_DIRENT;
		__builtin_memcpy(ctx->result.payload, "sample\n", 7);
		ctx->result.payload_len = 7;
		bpf_printk("tcpfs_s3: result readdir id=%llu payload_len=%u",
			   ctx->id, ctx->result.payload_len);
		return 0;
	}

	ctx->result.type = TCPFS_RESULT_ATTR;
	ctx->result.ino = ctx->ino ?: ctx->id + 1;
	ctx->result.size = 4096;
	ctx->result.mode = 0100444;
	bpf_printk("tcpfs_s3: result attr id=%llu size=%llu",
		   ctx->id, ctx->result.size);
	return 0;
#undef ctx
}

SEC("struct_ops/on_unsolicited")
int BPF_PROG(tcpfs_s3_on_unsolicited, struct tcpfs_ctx *tctx)
{
#define ctx tctx
	bpf_printk("tcpfs_s3: unsolicited id=%llu result_id=%llu",
		   ctx->id, ctx->result.id);
	return 0;
#undef ctx
}

SEC(".struct_ops.link")
struct tcpfs_ops tcpfs_s3 = {
	.name = "tcpfs_s3",
	.build_request = (void *)tcpfs_s3_build_request,
	.frame_tx = (void *)tcpfs_s3_frame_tx,
	.unframe_rx = (void *)tcpfs_s3_unframe_rx,
	.handle_response = (void *)tcpfs_s3_handle_response,
	.on_unsolicited = (void *)tcpfs_s3_on_unsolicited,
};

char _license[] SEC("license") = "GPL";
