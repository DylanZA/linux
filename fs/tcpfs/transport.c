// SPDX-License-Identifier: GPL-2.0
#include <linux/completion.h>
#include <linux/io_uring/cmd.h>
#include <linux/io_uring/zcrx_cmd.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tcp_states.h>

#include "tcpfs.h"

struct tcpfs_conn_pool {
	struct tcpfs_sb_info *sbi;
	struct socket *sock;
	/* Serializes ownership and I/O on the reusable socket. */
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

struct tcpfs_uring_pdu {
	/* Protects read publication against cancellation and completion. */
	spinlock_t lock;
	struct tcpfs_async_read *read;
};

struct tcpfs_async_read {
	struct io_uring_cmd *cmd;
	struct io_uring_zcrx_ifq *ifq;
	struct tcpfs_conn_pool *pool;
	struct tcpfs_ctx *ctx;
	struct socket *sock;
	void (*old_data_ready)(struct sock *sk);
	void (*old_write_space)(struct sock *sk);
	void (*old_state_change)(struct sock *sk);
	refcount_t refs;
	atomic_t scheduled;
	atomic_t pending;
	bool armed;
	bool connecting;
	bool sending;
	bool response_ready;
	bool done;
	bool pooled;
	bool close_sock;
	bool cancelled;
	size_t req_len;
	size_t sent;
	size_t copied;
	size_t target_len;
	size_t framing_len;
	size_t framing_consumed;
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

static u32 tcpfs_conn_style(const struct tcpfs_ops *ops)
{
	return ops->conn_style ?: TCPFS_CONN_NEW;
}

static int tcpfs_connect_locked(struct tcpfs_conn_pool *pool)
{
	struct tcpfs_sb_info *sbi = pool->sbi;
	struct tcpfs_server *server = &sbi->servers[0];
	struct socket *sock;
	int family, ret;

	if (pool->sock &&
	    READ_ONCE(pool->sock->sk->sk_state) != TCP_ESTABLISHED)
		tcpfs_close_locked(pool);
	if (pool->sock)
		return 0;

	pr_debug("tcpfs: connecting family=%d addrlen=%d\n",
		 ((struct sockaddr *)&server->addr)->sa_family,
		 server->addrlen);

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
	pr_debug("tcpfs: connected\n");
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

static void tcpfs_async_schedule(struct tcpfs_async_read *read);
static void tcpfs_async_task_work(struct io_tw_req tw_req, io_tw_token_t tw);

static void tcpfs_async_data_ready(struct sock *sk)
{
	struct tcpfs_async_read *read;
	void (*data_ready)(struct sock *sk);

	read_lock_bh(&sk->sk_callback_lock);
	read = sk->sk_user_data;
	if (read) {
		data_ready = read->old_data_ready;
		if (!READ_ONCE(read->done))
			tcpfs_async_schedule(read);
	} else {
		data_ready = sk->sk_data_ready;
		if (data_ready == tcpfs_async_data_ready)
			data_ready = NULL;
	}
	read_unlock_bh(&sk->sk_callback_lock);
	if (data_ready)
		data_ready(sk);
}

static void tcpfs_async_write_space(struct sock *sk)
{
	struct tcpfs_async_read *read;
	void (*write_space)(struct sock *sk);

	read_lock_bh(&sk->sk_callback_lock);
	read = sk->sk_user_data;
	if (read) {
		write_space = read->old_write_space;
		if (!READ_ONCE(read->done))
			tcpfs_async_schedule(read);
	} else {
		write_space = sk->sk_write_space;
		if (write_space == tcpfs_async_write_space)
			write_space = NULL;
	}
	read_unlock_bh(&sk->sk_callback_lock);
	if (write_space)
		write_space(sk);
}

static void tcpfs_async_state_change(struct sock *sk)
{
	struct tcpfs_async_read *read;
	void (*state_change)(struct sock *sk);

	read_lock_bh(&sk->sk_callback_lock);
	read = sk->sk_user_data;
	if (read) {
		state_change = read->old_state_change;
		if (!READ_ONCE(read->done))
			tcpfs_async_schedule(read);
	} else {
		state_change = sk->sk_state_change;
		if (state_change == tcpfs_async_state_change)
			state_change = NULL;
	}
	read_unlock_bh(&sk->sk_callback_lock);
	if (state_change)
		state_change(sk);
}

static void tcpfs_async_schedule(struct tcpfs_async_read *read)
{
	if (READ_ONCE(read->done))
		return;
	if (!READ_ONCE(read->armed)) {
		atomic_set(&read->pending, 1);
		return;
	}

	if (atomic_xchg(&read->scheduled, 1)) {
		atomic_set(&read->pending, 1);
		return;
	}
	io_uring_cmd_complete_in_task(read->cmd, tcpfs_async_task_work);
}

static void tcpfs_async_restore_socket(struct tcpfs_async_read *read)
{
	struct socket *sock = read->sock;

	if (!sock)
		return;

	write_lock_bh(&sock->sk->sk_callback_lock);
	if (sock->sk->sk_user_data == read) {
		sock->sk->sk_user_data = NULL;
		sock->sk->sk_data_ready = read->old_data_ready;
		sock->sk->sk_write_space = read->old_write_space;
		sock->sk->sk_state_change = read->old_state_change;
	}
	write_unlock_bh(&sock->sk->sk_callback_lock);
}

static void tcpfs_async_cleanup(struct tcpfs_async_read *read)
{
	tcpfs_async_restore_socket(read);
	if (read->pooled) {
		if (read->close_sock)
			tcpfs_close_locked(read->pool);
		mutex_unlock(&read->pool->sock_lock);
	} else if (read->sock) {
		sock_release(read->sock);
	}
	io_uring_cmd_zcrx_put(read->ifq);
	tcpfs_pool_put(read->pool);
	kfree(read->ctx);
	read->ifq = NULL;
	read->pool = NULL;
	read->ctx = NULL;
	read->sock = NULL;
}

static void tcpfs_async_put(struct tcpfs_async_read *read)
{
	if (refcount_dec_and_test(&read->refs))
		kfree(read);
}

static struct tcpfs_async_read *
tcpfs_async_pdu_get(struct tcpfs_uring_pdu *pdu)
{
	struct tcpfs_async_read *read;

	spin_lock(&pdu->lock);
	read = pdu->read;
	if (read)
		refcount_inc(&read->refs);
	spin_unlock(&pdu->lock);
	return read;
}

static void tcpfs_async_pdu_set(struct tcpfs_uring_pdu *pdu,
				struct tcpfs_async_read *read)
{
	spin_lock(&pdu->lock);
	pdu->read = read;
	spin_unlock(&pdu->lock);
}

static bool tcpfs_async_pdu_clear(struct tcpfs_uring_pdu *pdu,
				  struct tcpfs_async_read *read)
{
	bool cleared = false;

	spin_lock(&pdu->lock);
	if (pdu->read == read) {
		pdu->read = NULL;
		cleared = true;
	}
	spin_unlock(&pdu->lock);
	return cleared;
}

static int tcpfs_async_send(struct tcpfs_async_read *read)
{
	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
	};
	struct kvec iov;
	int ret;

	while (read->sent < read->req_len) {
		iov.iov_base = read->ctx->payload + read->sent;
		iov.iov_len = read->req_len - read->sent;

		ret = kernel_sendmsg(read->sock, &msg, &iov, 1, iov.iov_len);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK)
			return -EAGAIN;
		if (ret < 0)
			return ret;
		if (!ret)
			return -EPIPE;
		read->sent += ret;
	}

	read->sending = false;
	return 0;
}

static size_t tcpfs_read_result_len(struct tcpfs_ctx *ctx)
{
	if (ctx->result.flags & TCPFS_RESULT_F_SIZE_VALID)
		return min_t(size_t, ctx->result.size, ctx->len);
	if (ctx->result.flags & TCPFS_RESULT_F_STREAM)
		return ctx->result.size ? min_t(size_t, ctx->result.size,
						ctx->len) : ctx->len;
	return min_t(size_t, ctx->result.payload_len, ctx->len);
}

static int tcpfs_copy_result_payload(struct tcpfs_ctx *ctx, struct iov_iter *to,
				     size_t *copied)
{
	size_t n = min_t(size_t, ctx->result.payload_len, ctx->len);
	const void *payload = ctx->result.payload;
	size_t done;

	if (ctx->result.flags & TCPFS_RESULT_F_STREAM) {
		if (ctx->result.rx_offset > ctx->rx_len)
			return -EPROTO;
		if (n > ctx->rx_len - ctx->result.rx_offset)
			return -EAGAIN;
		payload = ctx->rx + ctx->result.rx_offset;
	}

	done = copy_to_iter(payload, n, to);
	*copied += done;
	return done == n ? 0 : -EFAULT;
}

static int tcpfs_recv_body_to_iter(struct socket *sock, struct tcpfs_ctx *ctx,
				   struct iov_iter *to, size_t *copied)
{
	size_t target = tcpfs_read_result_len(ctx);
	size_t buf_len = min_t(size_t, PAGE_SIZE, TCPFS_PAYLOAD_MAX);
	void *buf;
	int ret = 0;

	if (!(ctx->result.flags & TCPFS_RESULT_F_STREAM))
		return 0;
	if (*copied >= target)
		return 0;

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	while (*copied < target) {
		size_t want = min_t(size_t, buf_len, target - *copied);
		struct msghdr msg = {};
		struct kvec iov = {
			.iov_base = buf,
			.iov_len = want,
		};
		size_t done;

		ret = kernel_recvmsg(sock, &msg, &iov, 1, want, 0);
		if (ret < 0)
			break;
		if (!ret)
			break;

		done = copy_to_iter(buf, ret, to);
		*copied += done;
		if (done != ret) {
			ret = -EFAULT;
			break;
		}
	}

	kfree(buf);
	if (ret < 0 && *copied)
		return 0;
	return ret < 0 ? ret : 0;
}

static int tcpfs_async_peek_response(struct tcpfs_async_read *read)
{
	struct tcpfs_ctx *ctx = read->ctx;
	struct tcpfs_ops *ops = read->pool->sbi->bpf_ops->ops;
	struct kvec iov = {
		.iov_base = ctx->rx,
		.iov_len = min_t(size_t, read->pool->sbi->opts.buf_size,
				    sizeof(ctx->rx)),
	};
	int ret;

	ret = io_uring_cmd_zcrx_peek(read->ifq, read->sock, iov.iov_base,
				     iov.iov_len);
	pr_debug("tcpfs: async peek id=%llu ret=%d copied=%zu target=%zu state=%u\n",
		 read->ctx->id, ret, read->copied, read->target_len,
		 READ_ONCE(read->sock->sk->sk_state));
	if (ret == -EAGAIN || ret == -EWOULDBLOCK)
		return -EAGAIN;
	if (ret <= 0)
		return ret ?: -EPIPE;
	ctx->rx_len = ret;
	memset(&ctx->result, 0, sizeof(ctx->result));

	ret = ops->unframe_rx(ctx);
	if (ret)
		return ret;
	if (!ctx->frame_len || ctx->frame_len > ctx->rx_len)
		return -EPROTO;

	ret = ops->handle_response(ctx);
	if (ret)
		return ret;
	if (ctx->result.id && ctx->result.id != ctx->id) {
		if (ops->on_unsolicited)
			ops->on_unsolicited(ctx);
		return -EAGAIN;
	}
	if (ctx->result.error)
		return ctx->result.error;
	if (ctx->result.type != TCPFS_RESULT_DATA)
		return -EIO;
	if (!(ctx->result.flags & TCPFS_RESULT_F_STREAM))
		return -EOPNOTSUPP;
	if (ctx->result.rx_offset > ctx->rx_len)
		return -EPROTO;

	read->target_len = tcpfs_read_result_len(ctx);
	read->framing_len = ctx->result.rx_offset;
	read->response_ready = true;
	return 0;
}

static int tcpfs_async_consume_framing(struct tcpfs_async_read *read)
{
	size_t left;
	int ret;

	left = read->framing_len - read->framing_consumed;
	if (!left)
		return 0;
	ret = io_uring_cmd_zcrx_consume(read->sock,
					min_t(size_t, left, UINT_MAX));
	pr_debug("tcpfs: async framing id=%llu left=%zu ret=%d consumed=%zu\n",
		 read->ctx->id, left, ret, read->framing_consumed);
	if (ret == -EAGAIN || ret == -EWOULDBLOCK)
		return -EAGAIN;
	if (ret <= 0)
		return ret ?: -EPIPE;
	read->framing_consumed += ret;
	return read->framing_consumed == read->framing_len ? 0 : -EAGAIN;
}

static int tcpfs_async_recv_response(struct tcpfs_async_read *read,
				     unsigned int issue_flags)
{
	size_t left;
	int ret;

	if (!read->response_ready) {
		ret = tcpfs_async_peek_response(read);
		if (ret)
			return ret;
	}

	ret = tcpfs_async_consume_framing(read);
	if (ret)
		return ret;
	if (read->copied >= read->target_len)
		return read->copied;

	left = read->target_len - read->copied;
	ret = io_uring_cmd_zcrx_recv(read->cmd, read->ifq, read->sock,
				     min_t(size_t, left, UINT_MAX),
				     read->ctx->offset + read->copied,
				     issue_flags);
	pr_debug("tcpfs: async recv id=%llu left=%zu ret=%d copied=%zu state=%u shutdown=%u\n",
		 read->ctx->id, left, ret, read->copied,
		 READ_ONCE(read->sock->sk->sk_state),
		 READ_ONCE(read->sock->sk->sk_shutdown));
	if (ret > 0) {
		read->copied += ret;
		return read->copied >= read->target_len ? read->copied : -EAGAIN;
	}
	return ret;
}

static int tcpfs_async_drive(struct tcpfs_async_read *read,
			     unsigned int issue_flags)
{
	int ret;

	if (READ_ONCE(read->cancelled))
		return -ECANCELED;

	if (read->connecting) {
		int state = READ_ONCE(read->sock->sk->sk_state);

		if (state == TCP_ESTABLISHED) {
			read->connecting = false;
		} else if (state == TCP_CLOSE) {
			ret = sock_error(read->sock->sk);
			return ret ?: -ECONNRESET;
		} else {
			return -EAGAIN;
		}
	}

	if (read->sending) {
		ret = tcpfs_async_send(read);
		if (ret)
			return ret;
	}

	return tcpfs_async_recv_response(read, issue_flags);
}

static void tcpfs_async_task_work(struct io_tw_req tw_req, io_tw_token_t tw)
{
	struct io_uring_cmd *cmd = io_uring_cmd_from_tw(tw_req);
	struct tcpfs_uring_pdu *pdu =
		io_uring_cmd_to_pdu(cmd, struct tcpfs_uring_pdu);
	struct tcpfs_async_read *read = tcpfs_async_pdu_get(pdu);
	int ret;

	if (!read)
		return;

	ret = tcpfs_async_drive(read, IO_URING_CMD_TASK_WORK_ISSUE_FLAGS);
	if (ret == -EAGAIN) {
		atomic_set(&read->scheduled, 0);
		if (atomic_xchg(&read->pending, 0))
			tcpfs_async_schedule(read);
		tcpfs_async_put(read);
		return;
	}

	WRITE_ONCE(read->done, true);
	if (!tcpfs_async_pdu_clear(pdu, read)) {
		tcpfs_async_put(read);
		return;
	}
	if (ret < 0)
		read->close_sock = true;
	pr_debug("tcpfs: async read id=%llu bytes=%zu ret=%d\n",
		 read->ctx->id, read->copied, ret);
	tcpfs_async_cleanup(read);
	io_uring_cmd_done(read->cmd, ret, IO_URING_CMD_TASK_WORK_ISSUE_FLAGS);
	/* Drop the PDU owner and this task-work invocation's reference. */
	tcpfs_async_put(read);
	tcpfs_async_put(read);
}

int tcpfs_read_zc_async(struct tcpfs_sb_info *sbi, const char *path,
			u32 path_len, u64 ino, u64 offset, size_t len,
			u32 ifq_idx, struct io_uring_cmd *cmd,
			unsigned int issue_flags)
{
	struct tcpfs_uring_pdu *pdu =
		io_uring_cmd_to_pdu(cmd, struct tcpfs_uring_pdu);
	struct tcpfs_conn_pool *pool;
	struct tcpfs_async_read *read;
	struct tcpfs_server *server;
	struct tcpfs_ctx *ctx;
	struct socket *sock;
	struct tcpfs_ops *ops;
	u32 conn_style;
	int family, ret;
	bool need_connect = true;

	if (!sbi->bpf_ops || !sbi->bpf_ops->ops)
		return -ENOENT;
	if (!len)
		return 0;
	ops = sbi->bpf_ops->ops;
	conn_style = tcpfs_conn_style(ops);
	if (conn_style == TCPFS_CONN_OVERLAP)
		return -EOPNOTSUPP;
	spin_lock_init(&pdu->lock);
	pdu->read = NULL;

	pool = tcpfs_pool_get(sbi);
	if (!pool)
		return -ESHUTDOWN;

	ctx = kzalloc_obj(*ctx, GFP_NOWAIT);
	read = kzalloc_obj(*read, GFP_NOWAIT);
	if (!ctx || !read) {
		ret = -ENOMEM;
		goto err_alloc;
	}
	refcount_set(&read->refs, 1);
	ret = io_uring_cmd_zcrx_get(cmd, ifq_idx, &read->ifq);
	if (ret)
		goto err_alloc;

	ctx->op = TCPFS_OP_READ;
	ctx->ino = ino;
	ctx->id = atomic64_inc_return(&sbi->next_id);
	ctx->offset = offset;
	ctx->len = len;
	strscpy(ctx->path, path ?: "", sizeof(ctx->path));
	ctx->path_len = min_t(u32, path_len, strlen(ctx->path));
	if (sbi->opts.arg) {
		strscpy(ctx->mount_arg, sbi->opts.arg, sizeof(ctx->mount_arg));
		ctx->mount_arg_len = strlen(ctx->mount_arg);
	}

	ret = ops->build_request(ctx);
	if (ret)
		goto err_alloc;
	if (!ctx->payload_len || ctx->payload_len > TCPFS_PAYLOAD_MAX) {
		ret = -EINVAL;
		goto err_alloc;
	}
	ret = ops->frame_tx(ctx);
	if (ret)
		goto err_alloc;
	if (!ctx->payload_len || ctx->payload_len > TCPFS_PAYLOAD_MAX) {
		ret = -EINVAL;
		goto err_alloc;
	}

	server = &sbi->servers[0];
	family = ((struct sockaddr *)&server->addr)->sa_family;
	if (conn_style == TCPFS_CONN_SERIAL) {
		if (!mutex_trylock(&pool->sock_lock)) {
			ret = -EAGAIN;
			goto err_alloc;
		}
		sock = pool->sock;
		if (sock && READ_ONCE(sock->sk->sk_state) != TCP_ESTABLISHED) {
			tcpfs_close_locked(pool);
			sock = NULL;
		}
		if (sock) {
			need_connect = false;
		} else {
			ret = sock_create_kern(&init_net, family, SOCK_STREAM,
					       IPPROTO_TCP, &sock);
			if (ret)
				goto err_unlock;
			pool->sock = sock;
		}
		read->pooled = true;
	} else {
		ret = sock_create_kern(&init_net, family, SOCK_STREAM,
				       IPPROTO_TCP, &sock);
		if (ret)
			goto err_alloc;
	}

	read->cmd = cmd;
	read->pool = pool;
	read->ctx = ctx;
	read->sock = sock;
	read->req_len = ctx->payload_len;
	read->sending = true;
	atomic_set(&read->scheduled, 0);
	atomic_set(&read->pending, 0);
	tcpfs_async_pdu_set(pdu, read);

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data = read;
	read->old_data_ready = sock->sk->sk_data_ready;
	read->old_write_space = sock->sk->sk_write_space;
	read->old_state_change = sock->sk->sk_state_change;
	sock->sk->sk_data_ready = tcpfs_async_data_ready;
	sock->sk->sk_write_space = tcpfs_async_write_space;
	sock->sk->sk_state_change = tcpfs_async_state_change;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	pr_debug("tcpfs: async read id=%llu op=%s path=%.*s offset=%llu len=%llu bytes=%zu\n",
		 ctx->id, ops->name, ctx->path_len, ctx->path, ctx->offset,
		 ctx->len, read->req_len);

	if (need_connect) {
		ret = kernel_connect(sock, (struct sockaddr_unsized *)&server->addr,
				     server->addrlen, O_NONBLOCK);
		if (ret && ret != -EINPROGRESS)
			goto err_sock;
		read->connecting = ret == -EINPROGRESS;
	}

	ret = tcpfs_async_drive(read, issue_flags);
	if (ret != -EAGAIN) {
		WRITE_ONCE(read->done, true);
		tcpfs_async_pdu_clear(pdu, read);
		if (ret < 0)
			read->close_sock = true;
		tcpfs_async_cleanup(read);
		tcpfs_async_put(read);
		return ret;
	}

	io_uring_cmd_mark_cancelable(cmd, issue_flags);
	WRITE_ONCE(read->armed, true);
	if (atomic_xchg(&read->pending, 0))
		tcpfs_async_schedule(read);
	return -EIOCBQUEUED;

err_sock:
	WRITE_ONCE(read->done, true);
	tcpfs_async_pdu_clear(pdu, read);
	read->close_sock = true;
	tcpfs_async_cleanup(read);
	tcpfs_async_put(read);
	return ret;

err_unlock:
	mutex_unlock(&pool->sock_lock);
err_alloc:
	if (read)
		io_uring_cmd_zcrx_put(read->ifq);
	kfree(ctx);
	kfree(read);
	tcpfs_pool_put(pool);
	return ret;
}

int tcpfs_cancel_zc_async(struct io_uring_cmd *cmd)
{
	struct tcpfs_uring_pdu *pdu =
		io_uring_cmd_to_pdu(cmd, struct tcpfs_uring_pdu);
	struct tcpfs_async_read *read = tcpfs_async_pdu_get(pdu);

	if (!read)
		return 0;
	WRITE_ONCE(read->cancelled, true);
	tcpfs_async_schedule(read);
	tcpfs_async_put(read);
	return 0;
}

static int tcpfs_do_io_locked(struct tcpfs_conn_pool *pool,
			      struct tcpfs_ctx *ctx)
{
	struct tcpfs_sb_info *sbi = pool->sbi;
	struct tcpfs_ops *ops = sbi->bpf_ops->ops;
	u32 conn_style = tcpfs_conn_style(ops);
	size_t receive_limit;
	int ret, n;
	bool retried_send = false;

	if (conn_style == TCPFS_CONN_OVERLAP)
		return -EOPNOTSUPP;

	if (!ctx->mount_arg_len && sbi->opts.arg) {
		strscpy(ctx->mount_arg, sbi->opts.arg, sizeof(ctx->mount_arg));
		ctx->mount_arg_len = strlen(ctx->mount_arg);
	}

	pr_debug("tcpfs: op begin id=%llu op=%s path=%.*s offset=%llu len=%llu ops=%s\n",
		 ctx->id, tcpfs_op_name(ctx->op), ctx->path_len, ctx->path,
		 ctx->offset, ctx->len, ops->name);

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

	pr_debug("tcpfs: tcp send id=%llu op=%s bytes=%u\n",
		 ctx->id, tcpfs_op_name(ctx->op), ctx->payload_len);

retry_send:
	ret = tcpfs_send(pool->sock, ctx->payload, ctx->payload_len);
	if (ret) {
		if (!retried_send && conn_style == TCPFS_CONN_SERIAL &&
		    (ret == -EPIPE || ret == -ECONNRESET || ret == -ENOTCONN)) {
			pr_debug("tcpfs: reconnecting stale socket id=%llu op=%s err=%d\n",
				 ctx->id, tcpfs_op_name(ctx->op), ret);
			tcpfs_close_locked(pool);
			retried_send = true;
			ret = tcpfs_connect_locked(pool);
			if (ret)
				return ret;
			goto retry_send;
		}
		goto reset;
	}

	receive_limit = min_t(size_t, sbi->opts.buf_size, sizeof(ctx->rx));
	ctx->rx_len = 0;
	for (;;) {
		size_t remaining = receive_limit - ctx->rx_len;

		if (!remaining) {
			ret = -EMSGSIZE;
			goto reset;
		}
		n = tcpfs_recv_once(pool->sock, ctx->rx + ctx->rx_len,
				    remaining);
		if (n < 0) {
			ret = n;
			goto reset;
		}
		if (!n) {
			ret = -EPIPE;
			goto reset;
		}
		ctx->rx_len += n;
		pr_debug("tcpfs: tcp recv id=%llu op=%s bytes=%d total=%u\n",
			 ctx->id, tcpfs_op_name(ctx->op), n, ctx->rx_len);

		ctx->frame_len = 0;
		memset(&ctx->result, 0, sizeof(ctx->result));
		ret = ops->unframe_rx(ctx);
		if (ret == -EAGAIN)
			continue;
		if (ret) {
			pr_warn("tcpfs: unframe_rx failed id=%llu err=%d\n",
				ctx->id, ret);
			goto reset;
		}
		if (!ctx->frame_len || ctx->frame_len > ctx->rx_len) {
			ret = -EPROTO;
			goto reset;
		}

		ret = ops->handle_response(ctx);
		if (ret == -EAGAIN)
			continue;
		if (ret) {
			pr_warn("tcpfs: handle_response failed id=%llu err=%d\n",
				ctx->id, ret);
			goto reset;
		}
		break;
	}
	if (ctx->result.id && ctx->result.id != ctx->id) {
		if (ops->on_unsolicited)
			ops->on_unsolicited(ctx);
		ret = -EAGAIN;
		goto reset;
	}

	if (conn_style == TCPFS_CONN_NEW &&
	    !(ctx->result.flags & TCPFS_RESULT_F_STREAM))
		tcpfs_close_locked(pool);

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
		pr_debug("tcpfs: op end id=%llu op=%s status=0 result_type=%u result_error=%d payload_len=%u\n",
			 ctx->id, tcpfs_op_name(ctx->op), ctx->result.type,
			 ctx->result.error, ctx->result.payload_len);
	return req.status;
}

ssize_t tcpfs_read_to_iter(struct tcpfs_sb_info *sbi, const char *path,
			   u32 path_len, u64 ino, u64 offset, size_t len,
			   struct iov_iter *to)
{
	struct tcpfs_conn_pool *pool;
	struct tcpfs_ctx *ctx;
	ssize_t ret;

	if (!sbi->bpf_ops || !sbi->bpf_ops->ops)
		return -ENOENT;
	if (!len)
		return 0;

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->op = TCPFS_OP_READ;
	ctx->ino = ino;
	ctx->id = atomic64_inc_return(&sbi->next_id);
	ctx->offset = offset;
	ctx->len = len;
	strscpy(ctx->path, path ?: "", sizeof(ctx->path));
	ctx->path_len = min_t(u32, path_len, strlen(ctx->path));

	pool = tcpfs_pool_get(sbi);
	if (!pool) {
		ret = -ESHUTDOWN;
		goto out_ctx;
	}

	mutex_lock(&pool->sock_lock);
	ret = tcpfs_do_io_locked(pool, ctx);
	if (!ret)
		ret = ctx->result.error;
	if (!ret && ctx->result.type != TCPFS_RESULT_DATA)
		ret = -EIO;
	if (!ret) {
		size_t copied = 0;

		ret = tcpfs_copy_result_payload(ctx, to, &copied);
		if (!ret)
			ret = tcpfs_recv_body_to_iter(pool->sock, ctx, to,
						      &copied);
		if (!ret)
			ret = copied;
	}
	if (tcpfs_conn_style(sbi->bpf_ops->ops) == TCPFS_CONN_NEW)
		tcpfs_close_locked(pool);
	mutex_unlock(&pool->sock_lock);

	tcpfs_pool_put(pool);
out_ctx:
	kfree(ctx);
	return ret;
}

int tcpfs_pool_create(struct tcpfs_sb_info *sbi)
{
	struct tcpfs_conn_pool *pool;

	pool = kzalloc_obj(*pool, GFP_KERNEL);
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
