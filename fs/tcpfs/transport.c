// SPDX-License-Identifier: GPL-2.0
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include "tcpfs.h"

struct tcpfs_conn_pool {
	struct tcpfs_sb_info *sbi;
	struct socket *sock;
	struct mutex sock_lock;
	struct workqueue_struct *wq;
	refcount_t refs;
	struct completion zero_refs;
	atomic_t closing;
};

struct tcpfs_request {
	struct work_struct work;
	struct completion done;
	struct tcpfs_conn_pool *pool;
	struct tcpfs_ctx *ctx;
	int status;
};

static const char *tcpfs_op_name(u32 op)
{
	switch (op) {
	case TCPFS_OP_LOOKUP:
		return "lookup";
	case TCPFS_OP_GETATTR:
		return "getattr";
	case TCPFS_OP_READDIR:
		return "readdir";
	case TCPFS_OP_READ:
		return "read";
	default:
		return "unknown";
	}
}

static struct tcpfs_conn_pool *tcpfs_pool_get(struct tcpfs_sb_info *sbi)
{
	struct tcpfs_conn_pool *pool = sbi->pool;

	if (!pool || atomic_read(&pool->closing))
		return NULL;
	refcount_inc(&pool->refs);
	return pool;
}

static void tcpfs_pool_put(struct tcpfs_conn_pool *pool)
{
	if (refcount_dec_and_test(&pool->refs))
		complete(&pool->zero_refs);
}

static void tcpfs_close_locked(struct tcpfs_conn_pool *pool)
{
	if (pool->sock) {
		sock_release(pool->sock);
		pool->sock = NULL;
	}
}

static int tcpfs_connect_locked(struct tcpfs_conn_pool *pool)
{
	struct tcpfs_sb_info *sbi = pool->sbi;
	struct tcpfs_server *server = &sbi->servers[0];
	struct socket *sock;
	int family, ret;

	if (pool->sock)
		return 0;

	pr_info("tcpfs: connecting family=%d addrlen=%d\n",
		((struct sockaddr *)&server->addr)->sa_family, server->addrlen);

	family = ((struct sockaddr *)&server->addr)->sa_family;
	ret = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_TCP,
			       &sock);
	if (ret) {
		pr_warn("tcpfs: socket create failed err=%d\n", ret);
		return ret;
	}

	WRITE_ONCE(sock->sk->sk_rcvtimeo, msecs_to_jiffies(sbi->opts.timeout_ms));
	WRITE_ONCE(sock->sk->sk_sndtimeo, msecs_to_jiffies(sbi->opts.timeout_ms));

	ret = kernel_connect(sock, (struct sockaddr_unsized *)&server->addr,
			     server->addrlen, 0);
	if (ret) {
		pr_warn("tcpfs: connect failed err=%d\n", ret);
		sock_release(sock);
		return ret;
	}

	pool->sock = sock;
	pr_info("tcpfs: connected\n");
	return 0;
}

static int tcpfs_send(struct socket *sock, void *buf, size_t len)
{
	struct msghdr msg = {};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = len,
	};
	int ret;

	while (len) {
		iov.iov_len = len;
		ret = kernel_sendmsg(sock, &msg, &iov, 1, len);
		if (ret < 0)
			return ret;
		if (!ret)
			return -EPIPE;
		iov.iov_base += ret;
		len -= ret;
	}

	return 0;
}

static int tcpfs_recv_once(struct socket *sock, void *buf, size_t len)
{
	struct msghdr msg = {};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = len,
	};

	return kernel_recvmsg(sock, &msg, &iov, 1, len, 0);
}

static int tcpfs_recv_response_locked(struct tcpfs_conn_pool *pool,
				      struct tcpfs_ctx *ctx)
{
	struct tcpfs_sb_info *sbi = pool->sbi;
	size_t cap = min_t(size_t, sbi->opts.buf_size, sizeof(ctx->rx));
	size_t off = 0;
	int n;

	while (off < cap) {
		n = tcpfs_recv_once(pool->sock, ctx->rx + off, cap - off);
		if (n < 0)
			return n;
		if (!n)
			break;
		off += n;
	}

	if (!off)
		return -EPIPE;
	ctx->rx_len = off;
	return 0;
}

static int tcpfs_http_roundtrip_locked(struct tcpfs_conn_pool *pool,
				       struct tcpfs_ctx *ctx,
				       const char *req, size_t req_len)
{
	int ret;

	ctx->rx_len = 0;
	ctx->frame_len = 0;

	ret = tcpfs_connect_locked(pool);
	if (ret)
		return ret;

	pr_info("tcpfs: http send id=%llu op=%s bytes=%zu\n",
		ctx->id, tcpfs_op_name(ctx->op), req_len);

	ret = tcpfs_send(pool->sock, (void *)req, req_len);
	if (!ret)
		ret = tcpfs_recv_response_locked(pool, ctx);
	if (ret)
		pr_warn("tcpfs: http roundtrip failed id=%llu op=%s err=%d\n",
			ctx->id, tcpfs_op_name(ctx->op), ret);
	else
		pr_info("tcpfs: http recv id=%llu op=%s bytes=%u\n",
			ctx->id, tcpfs_op_name(ctx->op), ctx->rx_len);

	/* S3-compatible HTTP/1.1 servers usually close for these requests. */
	tcpfs_close_locked(pool);
	return ret;
}

static int tcpfs_http_status(const struct tcpfs_ctx *ctx)
{
	unsigned int code = 0;

	if (ctx->rx_len < 12 || memcmp(ctx->rx, "HTTP/", 5))
		return -EPROTO;
	if (ctx->rx[8] != ' ' ||
	    ctx->rx[9] < '0' || ctx->rx[9] > '9' ||
	    ctx->rx[10] < '0' || ctx->rx[10] > '9' ||
	    ctx->rx[11] < '0' || ctx->rx[11] > '9')
		return -EPROTO;

	code = (ctx->rx[9] - '0') * 100 + (ctx->rx[10] - '0') * 10 +
	       ctx->rx[11] - '0';
	return code;
}

static char *tcpfs_http_body(struct tcpfs_ctx *ctx, size_t *body_len)
{
	size_t i;

	for (i = 0; i + 3 < ctx->rx_len; i++) {
		if (ctx->rx[i] == '\r' && ctx->rx[i + 1] == '\n' &&
		    ctx->rx[i + 2] == '\r' && ctx->rx[i + 3] == '\n') {
			*body_len = ctx->rx_len - i - 4;
			return (char *)ctx->rx + i + 4;
		}
	}

	*body_len = 0;
	return NULL;
}

static u64 tcpfs_http_content_length(struct tcpfs_ctx *ctx)
{
	static const char header[] = "\r\nContent-Length:";
	char *p, *end;
	u64 len = 0;

	p = strnstr((char *)ctx->rx, header, ctx->rx_len);
	if (!p)
		return 0;
	p += sizeof(header) - 1;
	end = (char *)ctx->rx + ctx->rx_len;
	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	while (p < end && *p >= '0' && *p <= '9') {
		len = len * 10 + *p - '0';
		p++;
	}
	return len;
}

static void tcpfs_s3_set_error(struct tcpfs_ctx *ctx, int err)
{
	ctx->result.id = ctx->id;
	ctx->result.type = TCPFS_RESULT_ERROR;
	ctx->result.error = err;
}

static int tcpfs_s3_append(char *buf, size_t buflen, size_t *pos,
			   const char *src, size_t len)
{
	if (*pos + len >= buflen)
		return -ENAMETOOLONG;
	memcpy(buf + *pos, src, len);
	*pos += len;
	buf[*pos] = '\0';
	return 0;
}

static int tcpfs_s3_escape_append(char *buf, size_t buflen, size_t *pos,
				  const char *src, size_t len)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t i;

	for (i = 0; i < len; i++) {
		unsigned char c = src[i];

		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '/' || c == '-' ||
		    c == '_' || c == '.' || c == '~') {
			if (tcpfs_s3_append(buf, buflen, pos, (char *)&src[i], 1))
				return -ENAMETOOLONG;
			continue;
		}
		if (*pos + 3 >= buflen)
			return -ENAMETOOLONG;
		buf[(*pos)++] = '%';
		buf[(*pos)++] = hex[c >> 4];
		buf[(*pos)++] = hex[c & 0xf];
		buf[*pos] = '\0';
	}

	return 0;
}

static int tcpfs_s3_path(struct tcpfs_sb_info *sbi, struct tcpfs_ctx *ctx,
			 char *path, size_t pathlen, bool trailing_slash)
{
	size_t pos = 0;
	size_t bucket_len;

	if (!sbi->opts.bucket || !*sbi->opts.bucket)
		return -EINVAL;
	bucket_len = strlen(sbi->opts.bucket);

	if (tcpfs_s3_append(path, pathlen, &pos, "/", 1) ||
	    tcpfs_s3_escape_append(path, pathlen, &pos, sbi->opts.bucket,
				   bucket_len))
		return -ENAMETOOLONG;

	if (ctx->path_len) {
		if (tcpfs_s3_append(path, pathlen, &pos, "/", 1) ||
		    tcpfs_s3_escape_append(path, pathlen, &pos, ctx->path,
					   ctx->path_len))
			return -ENAMETOOLONG;
	}

	if (trailing_slash && (!pos || path[pos - 1] != '/')) {
		if (tcpfs_s3_append(path, pathlen, &pos, "/", 1))
			return -ENAMETOOLONG;
	}

	return 0;
}

static int tcpfs_s3_build_list_path(struct tcpfs_sb_info *sbi,
				    struct tcpfs_ctx *ctx, char *path,
				    size_t pathlen, bool max_keys_one)
{
	static const char list_query[] = "?list-type=2&delimiter=/";
	size_t pos = 0;

	if (!sbi->opts.bucket || !*sbi->opts.bucket)
		return -EINVAL;

	if (tcpfs_s3_append(path, pathlen, &pos, "/", 1) ||
	    tcpfs_s3_escape_append(path, pathlen, &pos, sbi->opts.bucket,
				   strlen(sbi->opts.bucket)) ||
	    tcpfs_s3_append(path, pathlen, &pos, list_query,
			    sizeof(list_query) - 1))
		return -ENAMETOOLONG;

	if (ctx->path_len) {
		if (tcpfs_s3_append(path, pathlen, &pos, "&prefix=", 8) ||
		    tcpfs_s3_escape_append(path, pathlen, &pos, ctx->path,
					   ctx->path_len) ||
		    tcpfs_s3_append(path, pathlen, &pos, "/", 1))
			return -ENAMETOOLONG;
	}

	if (max_keys_one &&
	    tcpfs_s3_append(path, pathlen, &pos, "&max-keys=1", 11))
		return -ENAMETOOLONG;

	return 0;
}

static int tcpfs_s3_request(char *req, size_t req_len, const char *method,
			    const char *path, const char *extra)
{
	int len;

	len = scnprintf(req, req_len,
			"%s %s HTTP/1.1\r\n"
			"Host: tcpfs-s3\r\n"
			"%s"
			"Connection: close\r\n\r\n",
			method, path, extra ?: "");
	if (len <= 0 || len >= req_len)
		return -ENAMETOOLONG;
	return len;
}

static bool tcpfs_s3_xml_has_entries(char *body, size_t body_len)
{
	return strnstr(body, "<Key>", body_len) ||
	       strnstr(body, "<Prefix>", body_len);
}

static int tcpfs_s3_head_object(struct tcpfs_conn_pool *pool,
				struct tcpfs_ctx *ctx, bool *exists)
{
	struct tcpfs_sb_info *sbi = pool->sbi;
	char path[TCPFS_PATH_MAX + TCPFS_BUCKET_MAX + 64];
	char req[512];
	int req_len, ret, status;

	ret = tcpfs_s3_path(sbi, ctx, path, sizeof(path), false);
	if (ret)
		return ret;
	req_len = tcpfs_s3_request(req, sizeof(req), "HEAD", path, NULL);
	if (req_len < 0)
		return req_len;

	pr_info("tcpfs: s3 HEAD id=%llu path=%s\n", ctx->id, path);

	ret = tcpfs_http_roundtrip_locked(pool, ctx, req, req_len);
	if (ret)
		return ret;

	status = tcpfs_http_status(ctx);
	pr_info("tcpfs: s3 HEAD id=%llu status=%d\n", ctx->id, status);
	if (status == 404 || status == 403) {
		*exists = false;
		return 0;
	}
	if (status < 200 || status >= 300)
		return -EIO;

	*exists = true;
	ctx->result.id = ctx->id;
	ctx->result.type = TCPFS_RESULT_ATTR;
	ctx->result.error = 0;
	ctx->result.ino = ctx->ino ?: ctx->id + 1;
	ctx->result.size = tcpfs_http_content_length(ctx);
	ctx->result.mode = S_IFREG | 0444;
	return 0;
}

static int tcpfs_s3_lookup_dir(struct tcpfs_conn_pool *pool,
			       struct tcpfs_ctx *ctx, bool *exists)
{
	struct tcpfs_sb_info *sbi = pool->sbi;
	char path[TCPFS_PATH_MAX + TCPFS_BUCKET_MAX + 128];
	char req[640];
	char *body;
	size_t body_len;
	int req_len, ret, status;

	ret = tcpfs_s3_build_list_path(sbi, ctx, path, sizeof(path), true);
	if (ret)
		return ret;
	req_len = tcpfs_s3_request(req, sizeof(req), "GET", path, NULL);
	if (req_len < 0)
		return req_len;

	pr_info("tcpfs: s3 LIST probe id=%llu path=%s\n", ctx->id, path);

	ret = tcpfs_http_roundtrip_locked(pool, ctx, req, req_len);
	if (ret)
		return ret;

	status = tcpfs_http_status(ctx);
	pr_info("tcpfs: s3 LIST probe id=%llu status=%d\n", ctx->id, status);
	if (status == 404 || status == 403) {
		*exists = false;
		return 0;
	}
	if (status < 200 || status >= 300)
		return -EIO;

	body = tcpfs_http_body(ctx, &body_len);
	*exists = body && tcpfs_s3_xml_has_entries(body, body_len);
	if (*exists) {
		ctx->result.id = ctx->id;
		ctx->result.type = TCPFS_RESULT_ATTR;
		ctx->result.error = 0;
		ctx->result.ino = ctx->ino ?: ctx->id + 1;
		ctx->result.size = 0;
		ctx->result.mode = S_IFDIR | 0555;
	}
	return 0;
}

static int tcpfs_s3_lookup_or_getattr(struct tcpfs_conn_pool *pool,
				      struct tcpfs_ctx *ctx)
{
	bool exists = false;
	int ret;

	ctx->result.id = ctx->id;
	if (!ctx->path_len) {
		pr_info("tcpfs: s3 root attr id=%llu\n", ctx->id);
		ctx->result.type = TCPFS_RESULT_ATTR;
		ctx->result.error = 0;
		ctx->result.ino = 1;
		ctx->result.size = 0;
		ctx->result.mode = S_IFDIR | 0555;
		return 0;
	}

	ret = tcpfs_s3_head_object(pool, ctx, &exists);
	if (ret)
		return ret;
	if (exists)
		return 0;

	ret = tcpfs_s3_lookup_dir(pool, ctx, &exists);
	if (ret)
		return ret;
	if (exists)
		return 0;

	tcpfs_s3_set_error(ctx, -ENOENT);
	return 0;
}

static int tcpfs_s3_emit_name(struct tcpfs_ctx *ctx, const char *name,
			      size_t name_len, bool dir)
{
	size_t pos = ctx->result.payload_len;

	if (!name_len)
		return 0;
	if (pos + name_len + (dir ? 2 : 1) > sizeof(ctx->result.payload))
		return 0;

	memcpy(ctx->result.payload + pos, name, name_len);
	pos += name_len;
	if (dir)
		ctx->result.payload[pos++] = '/';
	ctx->result.payload[pos++] = '\n';
	ctx->result.payload_len = pos;
	return 0;
}

static void tcpfs_s3_parse_list(struct tcpfs_ctx *ctx, char *body,
				size_t body_len)
{
	const char *prefix = ctx->path;
	size_t prefix_len = ctx->path_len;
	char *p = body, *end = body + body_len;

	if (prefix_len && prefix[prefix_len - 1] != '/')
		prefix_len++;

	while (p < end) {
		char *open, *close;
		const char *name;
		size_t len;
		bool dir = false;

		open = strnstr(p, "<CommonPrefixes>", end - p);
		if (open) {
			open = strnstr(open, "<Prefix>", end - open);
			close = open ? strnstr(open, "</Prefix>", end - open) : NULL;
			dir = true;
		} else {
			open = strnstr(p, "<Key>", end - p);
			close = open ? strnstr(open, "</Key>", end - open) : NULL;
		}
		if (!open || !close)
			break;

		open = strchr(open, '>');
		if (!open || open + 1 > close)
			break;
		name = open + 1;
		len = close - name;
		p = close + 1;

		if (ctx->path_len) {
			if (len < prefix_len ||
			    memcmp(name, prefix, ctx->path_len) ||
			    name[ctx->path_len] != '/')
				continue;
			name += prefix_len;
			len -= prefix_len;
		}
		if (dir && len && name[len - 1] == '/')
			len--;
		if (memchr(name, '/', len) && !dir)
			continue;
		tcpfs_s3_emit_name(ctx, name, len, dir);
	}
}

static int tcpfs_s3_readdir(struct tcpfs_conn_pool *pool, struct tcpfs_ctx *ctx)
{
	struct tcpfs_sb_info *sbi = pool->sbi;
	char path[TCPFS_PATH_MAX + TCPFS_BUCKET_MAX + 128];
	char req[640];
	char *body;
	size_t body_len;
	int req_len, ret, status;

	ret = tcpfs_s3_build_list_path(sbi, ctx, path, sizeof(path), false);
	if (ret)
		return ret;
	req_len = tcpfs_s3_request(req, sizeof(req), "GET", path, NULL);
	if (req_len < 0)
		return req_len;

	pr_info("tcpfs: s3 LIST id=%llu path=%s\n", ctx->id, path);

	ret = tcpfs_http_roundtrip_locked(pool, ctx, req, req_len);
	if (ret)
		return ret;
	status = tcpfs_http_status(ctx);
	pr_info("tcpfs: s3 LIST id=%llu status=%d\n", ctx->id, status);
	if (status < 200 || status >= 300)
		return -EIO;

	ctx->result.id = ctx->id;
	ctx->result.type = TCPFS_RESULT_DIRENT;
	ctx->result.error = 0;
	ctx->result.payload_len = 0;

	body = tcpfs_http_body(ctx, &body_len);
	if (body)
		tcpfs_s3_parse_list(ctx, body, body_len);
	pr_info("tcpfs: s3 LIST id=%llu entries_bytes=%u body_bytes=%zu\n",
		ctx->id, ctx->result.payload_len, body ? body_len : 0);
	return 0;
}

static int tcpfs_s3_read(struct tcpfs_conn_pool *pool, struct tcpfs_ctx *ctx)
{
	struct tcpfs_sb_info *sbi = pool->sbi;
	char path[TCPFS_PATH_MAX + TCPFS_BUCKET_MAX + 64];
	char extra[96];
	char req[768];
	char *body;
	size_t body_len, n;
	int req_len, ret, status;

	ret = tcpfs_s3_path(sbi, ctx, path, sizeof(path), false);
	if (ret)
		return ret;
	scnprintf(extra, sizeof(extra), "Range: bytes=%llu-%llu\r\n",
		  ctx->offset, ctx->offset + ctx->len - 1);
	req_len = tcpfs_s3_request(req, sizeof(req), "GET", path, extra);
	if (req_len < 0)
		return req_len;

	pr_info("tcpfs: s3 GET id=%llu path=%s offset=%llu len=%llu\n",
		ctx->id, path, ctx->offset, ctx->len);

	ret = tcpfs_http_roundtrip_locked(pool, ctx, req, req_len);
	if (ret)
		return ret;
	status = tcpfs_http_status(ctx);
	pr_info("tcpfs: s3 GET id=%llu status=%d\n", ctx->id, status);
	if (status == 404) {
		tcpfs_s3_set_error(ctx, -ENOENT);
		return 0;
	}
	if (status < 200 || status >= 300)
		return -EIO;

	body = tcpfs_http_body(ctx, &body_len);
	if (!body)
		return -EPROTO;

	n = min_t(size_t, body_len, min_t(size_t, ctx->len,
					 sizeof(ctx->result.payload)));
	memcpy(ctx->result.payload, body, n);
	ctx->result.id = ctx->id;
	ctx->result.type = TCPFS_RESULT_DATA;
	ctx->result.error = 0;
	ctx->result.offset = ctx->offset;
	ctx->result.payload_len = n;
	pr_info("tcpfs: s3 GET id=%llu bytes=%zu\n", ctx->id, n);
	return 0;
}

static int tcpfs_s3_do_io_locked(struct tcpfs_conn_pool *pool,
				 struct tcpfs_ctx *ctx)
{
	switch (ctx->op) {
	case TCPFS_OP_LOOKUP:
	case TCPFS_OP_GETATTR:
		return tcpfs_s3_lookup_or_getattr(pool, ctx);
	case TCPFS_OP_READDIR:
		return tcpfs_s3_readdir(pool, ctx);
	case TCPFS_OP_READ:
		return tcpfs_s3_read(pool, ctx);
	default:
		return -EOPNOTSUPP;
	}
}

static int tcpfs_do_io_locked(struct tcpfs_conn_pool *pool,
			      struct tcpfs_ctx *ctx)
{
	struct tcpfs_sb_info *sbi = pool->sbi;
	struct tcpfs_ops *ops = sbi->bpf_ops->ops;
	int ret, n;

	if (!ctx->bucket_len && sbi->opts.bucket) {
		strscpy(ctx->bucket, sbi->opts.bucket, sizeof(ctx->bucket));
		ctx->bucket_len = strlen(ctx->bucket);
	}

	pr_info("tcpfs: op begin id=%llu op=%s path=%.*s offset=%llu len=%llu ops=%s\n",
		ctx->id, tcpfs_op_name(ctx->op), ctx->path_len, ctx->path,
		ctx->offset, ctx->len, ops->name);

	if (!strcmp(ops->name, "tcpfs_s3"))
		return tcpfs_s3_do_io_locked(pool, ctx);

	ret = ops->build_request(ctx);
	if (ret) {
		pr_warn("tcpfs: build_request failed id=%llu err=%d\n",
			ctx->id, ret);
		return ret;
	}
	if (!ctx->payload_len || ctx->payload_len > TCPFS_PAYLOAD_MAX)
		return -EINVAL;

	ret = ops->frame_tx(ctx);
	if (ret) {
		pr_warn("tcpfs: frame_tx failed id=%llu err=%d\n", ctx->id, ret);
		return ret;
	}
	if (!ctx->payload_len || ctx->payload_len > TCPFS_PAYLOAD_MAX)
		return -EINVAL;

	ret = tcpfs_connect_locked(pool);
	if (ret)
		return ret;

	pr_info("tcpfs: tcp send id=%llu op=%s bytes=%u\n",
		ctx->id, tcpfs_op_name(ctx->op), ctx->payload_len);

	ret = tcpfs_send(pool->sock, ctx->payload, ctx->payload_len);
	if (ret)
		goto reset;

	n = tcpfs_recv_once(pool->sock, ctx->rx,
			    min_t(size_t, sbi->opts.buf_size, sizeof(ctx->rx)));
	if (n < 0) {
		ret = n;
		goto reset;
	}
	if (!n) {
		ret = -EPIPE;
		goto reset;
	}
	ctx->rx_len = n;
	pr_info("tcpfs: tcp recv id=%llu op=%s bytes=%d\n",
		ctx->id, tcpfs_op_name(ctx->op), n);

	ret = ops->unframe_rx(ctx);
	if (ret) {
		pr_warn("tcpfs: unframe_rx failed id=%llu err=%d\n",
			ctx->id, ret);
		return ret;
	}
	if (!ctx->frame_len || ctx->frame_len > ctx->rx_len)
		return -EPROTO;

	ret = ops->handle_response(ctx);
	if (ret) {
		pr_warn("tcpfs: handle_response failed id=%llu err=%d\n",
			ctx->id, ret);
		return ret;
	}
	if (ctx->result.id && ctx->result.id != ctx->id) {
		if (ops->on_unsolicited)
			ops->on_unsolicited(ctx);
		return -EAGAIN;
	}

	return 0;

reset:
	pr_warn("tcpfs: resetting connection id=%llu op=%s err=%d\n",
		ctx->id, tcpfs_op_name(ctx->op), ret);
	tcpfs_close_locked(pool);
	return ret;
}

static void tcpfs_request_work(struct work_struct *work)
{
	struct tcpfs_request *req = container_of(work, struct tcpfs_request, work);
	struct tcpfs_conn_pool *pool = req->pool;

	if (atomic_read(&pool->closing)) {
		req->status = -ESHUTDOWN;
		goto out;
	}

	mutex_lock(&pool->sock_lock);
	req->status = tcpfs_do_io_locked(pool, req->ctx);
	mutex_unlock(&pool->sock_lock);

out:
	complete(&req->done);
}

int tcpfs_call(struct tcpfs_sb_info *sbi, struct tcpfs_ctx *ctx)
{
	struct tcpfs_conn_pool *pool;
	struct tcpfs_request req;
	bool queued;

	if (!sbi->bpf_ops || !sbi->bpf_ops->ops)
		return -ENOENT;

	pool = tcpfs_pool_get(sbi);
	if (!pool)
		return -ESHUTDOWN;

	INIT_WORK(&req.work, tcpfs_request_work);
	init_completion(&req.done);
	req.pool = pool;
	req.ctx = ctx;
	req.status = 0;

	queued = queue_work(pool->wq, &req.work);
	if (!queued) {
		tcpfs_pool_put(pool);
		return -EIO;
	}

	wait_for_completion(&req.done);
	tcpfs_pool_put(pool);
	if (req.status)
		pr_warn("tcpfs: op end id=%llu op=%s status=%d result_type=%u result_error=%d\n",
			ctx->id, tcpfs_op_name(ctx->op), req.status,
			ctx->result.type, ctx->result.error);
	else
		pr_info("tcpfs: op end id=%llu op=%s status=0 result_type=%u result_error=%d payload_len=%u\n",
			ctx->id, tcpfs_op_name(ctx->op), ctx->result.type,
			ctx->result.error, ctx->result.payload_len);
	return req.status;
}

int tcpfs_pool_create(struct tcpfs_sb_info *sbi)
{
	struct tcpfs_conn_pool *pool;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return -ENOMEM;

	pool->sbi = sbi;
	mutex_init(&pool->sock_lock);
	refcount_set(&pool->refs, 1);
	init_completion(&pool->zero_refs);
	atomic_set(&pool->closing, 0);
	pool->wq = alloc_ordered_workqueue("tcpfs-%p", WQ_MEM_RECLAIM, sbi);
	if (!pool->wq) {
		kfree(pool);
		return -ENOMEM;
	}

	sbi->pool = pool;
	pr_info("tcpfs: pool created buf_size=%u buf_count=%u\n",
		sbi->opts.buf_size, sbi->opts.buf_count);
	return 0;
}

void tcpfs_pool_destroy(struct tcpfs_sb_info *sbi)
{
	struct tcpfs_conn_pool *pool = sbi->pool;

	if (!pool)
		return;
	sbi->pool = NULL;
	atomic_set(&pool->closing, 1);
	flush_workqueue(pool->wq);
	destroy_workqueue(pool->wq);
	mutex_lock(&pool->sock_lock);
	tcpfs_close_locked(pool);
	mutex_unlock(&pool->sock_lock);
	tcpfs_pool_put(pool);
	wait_for_completion(&pool->zero_refs);
	kfree(pool);
	pr_info("tcpfs: pool destroyed\n");
}
