// SPDX-License-Identifier: GPL-2.0
/*
 * Sample datafs BPF app that emits plaintext HTTP/1.1 requests compatible with
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
#include <linux/bpf.h>

#include "datafs_bpf.h"

#define S3_LIST_MAX		16
#define S3_KEY_OPEN		"<Key>"
#define S3_KEY_CLOSE		"</Key>"
#define S3_PREFIX_GROUP_OPEN	"<CommonPrefixes>"
#define S3_PREFIX_GROUP_CLOSE	"</CommonPrefixes>"
#define S3_PREFIX_OPEN		"<Prefix>"
#define S3_PREFIX_CLOSE		"</Prefix>"
#define S3_SOCKET_POOL_MAX	1024
#define TCPFS_EAGAIN		11
#define TCPFS_EACCES		13
#define TCPFS_EINVAL		22
#define TCPFS_ENOENT		2
#define TCPFS_EMSGSIZE		90
#define TCPFS_EPROTO		71
#define TCPFS_EREMOTEIO		121
#ifdef DATAFS_S3_DEBUG
#define S3_LOG(...)		bpf_printk(__VA_ARGS__)
#else
#define S3_LOG(...)		do { } while (0)
#endif

#define APPEND(ctx, literal) \
	bpf_tcpfs_payload_append_str((ctx), (literal))

DATAFS_DEFINE_SOCKET_LOAN(datafs_s3, datafs_s3_sock, datafs_s3_avail,
			  S3_SOCKET_POOL_MAX);

SEC("struct_ops/build_request")
int BPF_PROG(datafs_s3_build_request, struct tcpfs_build_request_ctx *tctx)
{
#define ctx (&tctx->output)
	int ret;

	S3_LOG("datafs_s3: build_request id=%llu op=%u path_len=%u",
	       ctx->id, ctx->op, ctx->path_len);

	if (!ctx->mount_arg_len)
		return -22;
	ctx->payload_len = 0;

	if (ctx->op == TCPFS_OP_READ) {
		__u64 end = ctx->offset + ctx->len - 1;

		if (!ctx->len || end < ctx->offset)
			return -22;

		ret = APPEND(ctx, "GET /");
		ret = ret ?: bpf_tcpfs_payload_append_mount_arg(ctx);
		if (ctx->path_len) {
			ret = ret ?: APPEND(ctx, "/");
			ret = ret ?: bpf_tcpfs_payload_append_path(ctx);
		}
		ret = ret ?: APPEND(ctx, " HTTP/1.1\r\nRange: bytes=");
		if (ret)
			return ret;
		ret = bpf_tcpfs_payload_append_u64(ctx, ctx->offset);
		ret = ret ?: APPEND(ctx, "-");
		ret = ret ?: bpf_tcpfs_payload_append_u64(ctx, end);
		ret = ret ?: APPEND(ctx, "\r\nHost: datafs-s3\r\n"
				    "Connection: keep-alive\r\n\r\n");
		if (ret)
			return ret;
		S3_LOG("datafs_s3: built read id=%llu payload_len=%u",
		       ctx->id, ctx->payload_len);
		return 0;
	}

	if (ctx->op == TCPFS_OP_READDIR) {
		ret = APPEND(ctx, "GET /");
		ret = ret ?: bpf_tcpfs_payload_append_mount_arg(ctx);
		ret = ret ?: APPEND(ctx,
					    "?list-type=2&delimiter=/&max-keys=16");
		if (ctx->path_len) {
			ret = ret ?: APPEND(ctx, "&prefix=");
			ret = ret ?: bpf_tcpfs_payload_append_path(ctx);
			ret = ret ?: APPEND(ctx, "/");
		}
		ret = ret ?: APPEND(ctx, " HTTP/1.1\r\nHost: datafs-s3\r\n"
					    "Connection: keep-alive\r\n\r\n");
		if (ret)
			return ret;
		S3_LOG("datafs_s3: built readdir id=%llu payload_len=%u",
		       ctx->id, ctx->payload_len);
		return 0;
	}

	if (!ctx->path_len) {
		ret = APPEND(ctx, "HEAD /");
		ret = ret ?: bpf_tcpfs_payload_append_mount_arg(ctx);
		ret = ret ?: APPEND(ctx, " HTTP/1.1\r\nHost: datafs-s3\r\n"
					    "Connection: keep-alive\r\n\r\n");
		if (ret)
			return ret;
		return 0;
	}

	ret = APPEND(ctx, "HEAD /");
	ret = ret ?: bpf_tcpfs_payload_append_mount_arg(ctx);
	ret = ret ?: APPEND(ctx, "/");
	ret = ret ?: bpf_tcpfs_payload_append_path(ctx);
	ret = ret ?: APPEND(ctx, " HTTP/1.1\r\nHost: datafs-s3\r\n"
				    "Connection: keep-alive\r\n\r\n");
	if (ret)
		return ret;
	S3_LOG("datafs_s3: built attr id=%llu payload_len=%u",
	       ctx->id, ctx->payload_len);
	return 0;
#undef ctx
}

SEC("struct_ops/frame_tx")
int BPF_PROG(datafs_s3_frame_tx, struct tcpfs_frame_tx_ctx *tctx)
{
#define ctx (&tctx->output)
	S3_LOG("datafs_s3: frame_tx id=%llu payload_len=%u",
	       ctx->id, ctx->payload_len);
	return ctx->payload_len ? 0 : -22;
#undef ctx
}

static __always_inline int s3_http_status(struct tcpfs_ctx *ctx)
{
	int hundreds, tens, ones;

	if (ctx->rx_len < 12)
		return -TCPFS_EAGAIN;
	if (ctx->rx[0] != 'H' || ctx->rx[1] != 'T' || ctx->rx[2] != 'T' ||
	    ctx->rx[3] != 'P' || ctx->rx[4] != '/' || ctx->rx[8] != ' ')
		return -TCPFS_EPROTO;
	hundreds = ctx->rx[9] - '0';
	tens = ctx->rx[10] - '0';
	ones = ctx->rx[11] - '0';
	if (hundreds < 0 || hundreds > 9 || tens < 0 || tens > 9 ||
	    ones < 0 || ones > 9)
		return -TCPFS_EPROTO;
	return hundreds * 100 + tens * 10 + ones;
}

static __always_inline int s3_content_length(struct tcpfs_ctx *ctx,
					     __u64 *length)
{
	int offset;

	offset = bpf_tcpfs_rx_find_str(ctx, "Content-Length:");
	if (offset < 0)
		return offset;
	return bpf_tcpfs_rx_parse_u64(ctx, offset + 15, length);
}

struct s3_list_state {
	struct tcpfs_ctx *ctx;
	__u32 pos;
	__u32 body_end;
	__s32 error;
};

static long s3_list_entry_cb(__u32 i, void *data)
{
	struct s3_list_state *state = data;
	struct tcpfs_ctx *ctx = state->ctx;
	__u32 start, len, next, rx_offset;
	int key_open, group_open, close, last, ret;
	int directory;
	char separator;

	if (i >= S3_LIST_MAX || state->error)
		return 1;
	key_open = bpf_tcpfs_rx_find_str_from(ctx, state->pos, S3_KEY_OPEN);
	group_open = bpf_tcpfs_rx_find_str_from(ctx, state->pos,
						S3_PREFIX_GROUP_OPEN);
	if (key_open < 0 && group_open < 0)
		return 1;
	directory = group_open >= 0 &&
		    (key_open < 0 || group_open < key_open);

	if (directory) {
		int group_close, prefix_open;

		group_close = bpf_tcpfs_rx_find_str_from(ctx, group_open,
							 S3_PREFIX_GROUP_CLOSE);
		prefix_open = bpf_tcpfs_rx_find_str_from(ctx, group_open,
							 S3_PREFIX_OPEN);
		if (group_close < 0 || prefix_open < 0 ||
		    prefix_open >= group_close) {
			state->error = -TCPFS_EPROTO;
			return 1;
		}
		start = prefix_open + sizeof(S3_PREFIX_OPEN) - 1;
		close = bpf_tcpfs_rx_find_str_from(ctx, start, S3_PREFIX_CLOSE);
		if (close < 0 || close > group_close) {
			state->error = -TCPFS_EPROTO;
			return 1;
		}
		next = group_close + sizeof(S3_PREFIX_GROUP_CLOSE) - 1;
	} else {
		start = key_open + sizeof(S3_KEY_OPEN) - 1;
		close = bpf_tcpfs_rx_find_str_from(ctx, start, S3_KEY_CLOSE);
		if (close < 0) {
			state->error = -TCPFS_EPROTO;
			return 1;
		}
		next = close + sizeof(S3_KEY_CLOSE) - 1;
	}
	if ((__u32)close > state->body_end || next > state->body_end) {
		state->error = -TCPFS_EPROTO;
		return 1;
	}
	state->pos = next;
	len = close - start;

	if (ctx->path_len) {
		if (len <= ctx->path_len) {
			if (len == ctx->path_len)
				return 0;
			state->error = -TCPFS_EPROTO;
			return 1;
		}
		rx_offset = __builtin_offsetof(struct tcpfs_ctx, rx) + start +
			    ctx->path_len;
		last = bpf_tcpfs_ctx_read_byte(ctx, rx_offset);
		if (last != '/') {
			state->error = -TCPFS_EPROTO;
			return 1;
		}
		start += ctx->path_len + 1;
		len -= ctx->path_len + 1;
	}
	if (!len)
		return 0;

	rx_offset = __builtin_offsetof(struct tcpfs_ctx, rx) + start + len - 1;
	last = bpf_tcpfs_ctx_read_byte(ctx, rx_offset);
	if (last < 0) {
		state->error = last;
		return 1;
	}
	if (len + 2 > TCPFS_PAYLOAD_MAX - ctx->result.payload_len)
		return 1;
	ret = bpf_tcpfs_result_append_rx(ctx, start, len);
	if (ret) {
		state->error = ret;
		return 1;
	}
	if (directory && last != '/') {
		separator = '/';
		ret = bpf_tcpfs_result_append(ctx, &separator, sizeof(separator));
		if (ret) {
			state->error = ret;
			return 1;
		}
	}
	separator = '\n';
	ret = bpf_tcpfs_result_append(ctx, &separator, sizeof(separator));
	if (ret) {
		state->error = ret;
		return 1;
	}
	return 0;
}

static __noinline int s3_parse_list(struct tcpfs_ctx *ctx, __u32 body)
{
	struct s3_list_state state = {
		.ctx = ctx,
		.pos = body,
		.body_end = ctx->rx_len,
	};
	int end;

	end = bpf_tcpfs_rx_find_str_from(ctx, body, "</ListBucketResult>");
	if (end == -TCPFS_ENOENT)
		return -TCPFS_EAGAIN;
	if (end < 0)
		return -TCPFS_EPROTO;
	if ((__u32)end >= state.body_end)
		return -TCPFS_EPROTO;
	bpf_loop(S3_LIST_MAX, s3_list_entry_cb, &state, 0);
	return state.error;
}

SEC("struct_ops/unframe_rx")
int BPF_PROG(datafs_s3_unframe_rx,
	     const struct tcpfs_unframe_rx_ctx *rx_ctx)
{
	int body;

	body = tcpfs_unframe_rx_find_str(rx_ctx, "\r\n\r\n");
	if (body < 0)
		return 0;
	return body + 4;
}

SEC("struct_ops/handle_response")
int BPF_PROG(datafs_s3_handle_response,
	     struct tcpfs_handle_response_ctx *tctx)
{
#define ctx (&tctx->output)
	int status;

	S3_LOG("datafs_s3: handle_response id=%llu op=%u rx_len=%u",
	       ctx->id, ctx->op, ctx->rx_len);

	ctx->result.id = ctx->id;
	ctx->result.error = 0;
	status = s3_http_status(ctx);
	if (status < 0)
		return status;
	if ((ctx->op == TCPFS_OP_READ && status != 206) ||
	    (ctx->op != TCPFS_OP_READ && status != 200)) {
		ctx->result.type = TCPFS_RESULT_ERROR;
		if (status == 404)
			ctx->result.error = -TCPFS_ENOENT;
		else if (status == 401 || status == 403)
			ctx->result.error = -TCPFS_EACCES;
		else
			ctx->result.error = -TCPFS_EREMOTEIO;
		return 0;
	}

	if (ctx->op == TCPFS_OP_READ) {
		int body = bpf_tcpfs_rx_find_str(ctx, "\r\n\r\n");
		__u64 body_len = 0;
		__u32 n;
		int ret;

		if (body < 0)
			return -TCPFS_EAGAIN;
		body += 4;
		ret = s3_content_length(ctx, &body_len);
		if (ret || body_len > ctx->len)
			return -TCPFS_EPROTO;
		n = ctx->rx_len - body;
		if (n > body_len)
			n = body_len;
		if (n > TCPFS_PAYLOAD_MAX)
			n = TCPFS_PAYLOAD_MAX;
		ctx->result.type = TCPFS_RESULT_DATA;
		ctx->result.flags = TCPFS_RESULT_F_SIZE_VALID;
		ctx->result.offset = ctx->offset;
		ctx->result.size = body_len;
		ctx->result.rx_run.data_len = body_len;
		ctx->result.rx_run.wire_len = body_len;
		ctx->result.rx_run.rx_offset = body;
		ctx->result.rx_run.flags = TCPFS_RX_RUN_F_FRAME_END;
		ctx->result.payload_len = n;
		S3_LOG("datafs_s3: result read id=%llu rx_offset=%u payload_len=%u size=%llu",
		       ctx->id, ctx->result.rx_run.rx_offset,
		       ctx->result.payload_len, ctx->result.size);
		return 0;
	}

	if (ctx->op == TCPFS_OP_READDIR) {
		int body = bpf_tcpfs_rx_find_str(ctx, "\r\n\r\n");
		int ret;

		if (body < 0)
			return -TCPFS_EPROTO;
		ctx->result.type = TCPFS_RESULT_DIRENT;
		ctx->result.payload_len = 0;
		ret = s3_parse_list(ctx, body + 4);
		if (ret)
			return ret;
		S3_LOG("datafs_s3: result readdir id=%llu payload_len=%u",
		       ctx->id, ctx->result.payload_len);
		return 0;
	}

	ctx->result.type = TCPFS_RESULT_ATTR;
	ctx->result.ino = ctx->ino ?: ctx->id + 1;
	if (ctx->path_len) {
		__u64 body_len;
		int ret;

		ret = s3_content_length(ctx, &body_len);
		if (ret)
			return -TCPFS_EPROTO;
		ctx->result.size = body_len;
	} else {
		ctx->result.size = 0;
	}
	ctx->result.flags |= TCPFS_RESULT_F_SIZE_VALID;
	ctx->result.mode = ctx->path_len ? 0100444 : 0040555;
	S3_LOG("datafs_s3: result attr id=%llu size=%llu",
	       ctx->id, ctx->result.size);
	return 0;
#undef ctx
}

SEC("struct_ops/recv_response")
int BPF_PROG(datafs_s3_recv_response,
	     struct tcpfs_recv_response_ctx *tctx)
{
#define ctx (&tctx->output)
	int body = bpf_tcpfs_rx_find_str(ctx, "\r\n\r\n");

	ctx->rx_need = 0;
	if (body < 0) {
		ctx->rx_need = ctx->rx_len + 256;
		if (ctx->rx_need > TCPFS_PAYLOAD_MAX)
			ctx->rx_need = TCPFS_PAYLOAD_MAX;
		if (ctx->rx_need == ctx->rx_len)
			return -TCPFS_EMSGSIZE;
		return -TCPFS_EAGAIN;
	}
	ctx->result.id = 0;
	ctx->frame_len = body + 4;
	return 0;
#undef ctx
}

SEC(".struct_ops.link")
struct tcpfs_ops datafs_s3 = {
	.name = "datafs_s3",
	.conn_style = TCPFS_CONN_SERIAL,
	.build_request = (void *)datafs_s3_build_request,
	.frame_tx = (void *)datafs_s3_frame_tx,
	.recv_response = (void *)datafs_s3_recv_response,
	.unframe_rx = (void *)datafs_s3_unframe_rx,
	.handle_response = (void *)datafs_s3_handle_response,
	.loan_socket = (void *)datafs_s3_loan_socket,
	.return_socket = (void *)datafs_s3_return_socket,
};

char _license[] SEC("license") = "GPL";
