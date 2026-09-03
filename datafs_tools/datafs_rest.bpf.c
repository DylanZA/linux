// SPDX-License-Identifier: GPL-2.0
/* HTTP/1.1 datafs provider for the userspace OpenAPI dispatch service. */
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

#define REST_EAGAIN 11
#define REST_EACCES 13
#define REST_ENOENT 2
#define REST_EINVAL 22
#define REST_EMSGSIZE 90
#define REST_EPROTO 71
#define REST_EREMOTEIO 121

static const char rest_schema_prefix[] = ".schema";

static __always_inline int rest_is_schema(const struct tcpfs_ctx *ctx)
{
	__u32 i;

	if (ctx->path_len < sizeof(rest_schema_prefix) - 1)
		return 0;
#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(rest_schema_prefix) - 1; i++)
		if (ctx->path[i] != rest_schema_prefix[i])
			return 0;
	return ctx->path_len == sizeof(rest_schema_prefix) - 1 ||
	       ctx->path[sizeof(rest_schema_prefix) - 1] == '/';
}

static __always_inline int rest_append_dispatch(struct tcpfs_ctx *ctx,
						const char *kind__str)
{
	int ret = bpf_tcpfs_payload_append_str(ctx, "/.__datafs/");

	ret = ret ?: bpf_tcpfs_payload_append_str(ctx, kind__str);
	if (ctx->path_len) {
		ret = ret ?: bpf_tcpfs_payload_append_str(ctx, "/");
		ret = ret ?: bpf_tcpfs_payload_append_path(ctx);
	}
	return ret;
}

static __always_inline int rest_append_endpoint(struct tcpfs_ctx *ctx)
{
	int ret = bpf_tcpfs_payload_append_mount_arg(ctx);

	if (ctx->path_len) {
		ret = ret ?: bpf_tcpfs_payload_append_str(ctx, "/");
		ret = ret ?: bpf_tcpfs_payload_append_path(ctx);
	}
	return ret;
}

SEC("struct_ops/build_request")
int BPF_PROG(datafs_rest_build_request, struct tcpfs_build_request_ctx *tctx)
{
#define ctx (&tctx->output)
	int ret;

	if (!ctx->mount_arg_len)
		return -REST_EINVAL;
	ctx->payload_len = 0;
	if (ctx->op == TCPFS_OP_READ) {
		__u64 end;

		if (!ctx->len)
			return -REST_EINVAL;
		end = ctx->offset + ctx->len - 1;
		if (end < ctx->offset)
			return -REST_EINVAL;
		ret = bpf_tcpfs_payload_append_str(ctx, "GET ");
		if (rest_is_schema(ctx))
			ret = ret ?: rest_append_dispatch(ctx, "schema");
		else
			ret = ret ?: rest_append_endpoint(ctx);
		ret = ret ?: bpf_tcpfs_payload_append_str(ctx,
			" HTTP/1.1\r\nRange: bytes=");
		ret = ret ?: bpf_tcpfs_payload_append_u64(ctx, ctx->offset);
		ret = ret ?: bpf_tcpfs_payload_append_str(ctx, "-");
		ret = ret ?: bpf_tcpfs_payload_append_u64(ctx, end);
	} else if (ctx->op == TCPFS_OP_READDIR) {
		ret = bpf_tcpfs_payload_append_str(ctx, "GET ");
		ret = ret ?: rest_append_dispatch(ctx, "dir");
	} else {
		ret = bpf_tcpfs_payload_append_str(ctx, "HEAD ");
		ret = ret ?: rest_append_dispatch(ctx, "meta");
	}
	if (ctx->op == TCPFS_OP_READ)
		ret = ret ?: bpf_tcpfs_payload_append_str(ctx,
			"\r\nHost: datafs-rest\r\nConnection: keep-alive\r\n\r\n");
	else
		ret = ret ?: bpf_tcpfs_payload_append_str(ctx,
			" HTTP/1.1\r\nHost: datafs-rest\r\nConnection: keep-alive\r\n\r\n");
	return ret;
#undef ctx
}

SEC("struct_ops/frame_tx")
int BPF_PROG(datafs_rest_frame_tx, struct tcpfs_frame_tx_ctx *tctx)
{
	return tctx->output.payload_len ? 0 : -REST_EINVAL;
}

static __always_inline int rest_http_status(struct tcpfs_ctx *ctx)
{
	int a, b, c;

	if (ctx->rx_len < 12)
		return -REST_EAGAIN;
	if (ctx->rx[0] != 'H' || ctx->rx[1] != 'T' || ctx->rx[2] != 'T' ||
	    ctx->rx[3] != 'P' || ctx->rx[4] != '/' || ctx->rx[8] != ' ')
		return -REST_EPROTO;
	a = ctx->rx[9] - '0';
	b = ctx->rx[10] - '0';
	c = ctx->rx[11] - '0';
	if (a < 0 || a > 9 || b < 0 || b > 9 || c < 0 || c > 9)
		return -REST_EPROTO;
	return a * 100 + b * 10 + c;
}

static __always_inline int rest_header_u64(struct tcpfs_ctx *ctx,
					   const char *name__str, __u64 *value)
{
	int offset = bpf_tcpfs_rx_find_str(ctx, name__str);

	if (offset < 0)
		return offset;
	return bpf_tcpfs_rx_parse_u64(ctx, offset + __builtin_strlen(name__str),
					value);
}

static __always_inline int rest_error(struct tcpfs_ctx *ctx, int status)
{
	ctx->result.type = TCPFS_RESULT_ERROR;
	if (status == 404)
		ctx->result.error = -REST_ENOENT;
	else if (status == 401 || status == 403)
		ctx->result.error = -REST_EACCES;
	else
		ctx->result.error = -REST_EREMOTEIO;
	return 0;
}

SEC("struct_ops/unframe_rx")
int BPF_PROG(datafs_rest_unframe_rx,
	     const struct tcpfs_unframe_rx_ctx *rx_ctx)
{
	int body = tcpfs_unframe_rx_find_str(rx_ctx, "\r\n\r\n");

	return body < 0 ? 0 : body + 4;
}

SEC("struct_ops/handle_response")
int BPF_PROG(datafs_rest_handle_response,
	     struct tcpfs_handle_response_ctx *tctx)
{
#define ctx (&tctx->output)
	int status = rest_http_status(ctx);
	__u64 length = 0;

	ctx->result.id = ctx->id;
	ctx->result.error = 0;
	if (status < 0)
		return status;
	if (status != 200 && status != 206)
		return rest_error(ctx, status);
	if (rest_header_u64(ctx, "Content-Length:", &length))
		return -REST_EPROTO;

	if (ctx->op == TCPFS_OP_READ) {
		int body = bpf_tcpfs_rx_find_str(ctx, "\r\n\r\n");
		__u32 n;

		if ((status == 200 && ctx->offset) || body < 0 ||
		    length > ctx->len)
			return -REST_EPROTO;
		body += 4;
		n = ctx->rx_len - body;
		if (n > length)
			n = length;
		ctx->result.type = TCPFS_RESULT_DATA;
		ctx->result.offset = ctx->offset;
		ctx->result.rx_run.data_len = length;
		ctx->result.rx_run.wire_len = length;
		ctx->result.rx_run.rx_offset = body;
		ctx->result.rx_run.flags = TCPFS_RX_RUN_F_FRAME_END;
		ctx->result.payload_len = n;
		return 0;
	}

	if (ctx->op == TCPFS_OP_READDIR) {
		int body = bpf_tcpfs_rx_find_str(ctx, "\r\n\r\n");

		if (body < 0 || length > TCPFS_PAYLOAD_MAX ||
		    ctx->rx_len - body - 4 < length)
			return -REST_EPROTO;
		ctx->result.type = TCPFS_RESULT_DIRENT;
		ctx->result.payload_len = 0;
		return bpf_tcpfs_result_append_rx(ctx, body + 4, length);
	}

	{
		__u64 kind = 0, ino = 0;

		if (rest_header_u64(ctx, "X-Datafs-Kind:", &kind) ||
		    rest_header_u64(ctx, "X-Datafs-Ino:", &ino) ||
		    kind < 1 || kind > 3)
			return -REST_EPROTO;
		ctx->result.type = TCPFS_RESULT_ATTR;
		ctx->result.ino = ino;
		ctx->result.flags = TCPFS_RESULT_F_SIZE_VALID;
		ctx->result.mode = kind == 2 ? 0040555 : 0100444;
		ctx->result.size = kind == 2 ? 0 : length;
	}
	return 0;
#undef ctx
}

SEC("struct_ops/recv_response")
int BPF_PROG(datafs_rest_recv_response,
	     struct tcpfs_recv_response_ctx *tctx)
{
#define ctx (&tctx->output)
	int body = bpf_tcpfs_rx_find_str(ctx, "\r\n\r\n");
	__u64 length = 0;

	ctx->rx_need = 0;
	if (body < 0) {
		ctx->rx_need = ctx->rx_len + 256;
		if (ctx->rx_need > TCPFS_PAYLOAD_MAX)
			ctx->rx_need = TCPFS_PAYLOAD_MAX;
		if (ctx->rx_need == ctx->rx_len)
			return -REST_EMSGSIZE;
		return -REST_EAGAIN;
	}
	body += 4;
	if (bpf_tcpfs_rx_find_str(ctx, "X-Datafs-Local:") >= 0) {
		if (rest_header_u64(ctx, "Content-Length:", &length) ||
		    length > (__u32)(TCPFS_PAYLOAD_MAX - body))
			return -REST_EMSGSIZE;
		if (ctx->rx_len < body + length) {
			ctx->rx_need = body + length;
			return -REST_EAGAIN;
		}
	}
	ctx->result.id = 0;
	ctx->frame_len = body + length;
	return 0;
#undef ctx
}

SEC(".struct_ops.link")
struct tcpfs_ops datafs_rest = {
	.name = "datafs_rest",
	.conn_style = TCPFS_CONN_SERIAL,
	.build_request = (void *)datafs_rest_build_request,
	.frame_tx = (void *)datafs_rest_frame_tx,
	.recv_response = (void *)datafs_rest_recv_response,
	.unframe_rx = (void *)datafs_rest_unframe_rx,
	.handle_response = (void *)datafs_rest_handle_response,
};

char _license[] SEC("license") = "GPL";
