// SPDX-License-Identifier: GPL-2.0
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "datafs.h"

#define DATAFS_MAX_EXCHANGES	8

struct datafs_connection {
	struct list_head link;
	struct socket *sock;
};

struct datafs_conn_pool {
	struct semaphore slots;
	/* Protects idle connections. */
	struct mutex lock;
	struct list_head idle;
};

struct datafs_async_read {
	struct list_head link;
	struct datafs_async_transport *transport;
	struct netfs_io_subrequest *subreq;
	struct tcpfs_ctx *ctx;
	bool prepared;
	unsigned int exchanges;
	size_t sent;
	size_t copied;
};

struct datafs_async_transport {
	struct datafs_sb_info *sbi;
	struct socket *sock;
	struct mutex lock;
	struct list_head queued;
	struct list_head pending;
	struct delayed_work work;
	wait_queue_entry_t socket_wait;
	struct timer_list timer;
	bool socket_waiting;
	bool worker_active;
	bool timed_out;
	bool stopped;
	u8 *rx;
	size_t rx_len;
};

static int datafs_async_transport_init(struct datafs_sb_info *sbi);
static void datafs_async_transport_destroy(struct datafs_sb_info *sbi);

/**
 * datafs_async_schedule() - Queue transport progress work immediately.
 * @transport: asynchronous transport to resume
 *
 * Socket and timeout callbacks use this helper to resume a request after the
 * exchange has returned -EIOCBQUEUED to its caller.
 */
static void datafs_async_schedule(struct datafs_async_transport *transport)
{
	mod_delayed_work(system_dfl_wq, &transport->work, 0);
}

/**
 * datafs_conn_style() - Return the provider's connection policy.
 * @sbi: superblock whose provider policy is returned
 *
 * Defaults to one-shot (TCPFS_CONN_NEW) when the provider leaves the policy at
 * zero.
 */
static u32 datafs_conn_style(const struct datafs_sb_info *sbi)
{
	return sbi->ops->conn_style ?: TCPFS_CONN_NEW;
}

/**
 * datafs_bpf_unframe_rx() - Ask BPF for the response bytes to decode.
 * @callback: provider unframe callback
 * @data: receive-window bytes
 * @len: receive-window length
 * @frame_len: returned bytes to expose to handle_response
 *
 * The unframe callback has no mutable output. A zero return means the window
 * is incomplete and the transport must receive more bytes.
 *
 * Return: 0 with @frame_len set, -EAGAIN when more bytes are required, or a
 * negative protocol error.
 */
int datafs_bpf_unframe_rx(
	int (*callback)(const struct tcpfs_unframe_rx_ctx *ctx),
	const void *data, size_t len, size_t *frame_len)
{
	struct tcpfs_unframe_rx_ctx input = {
		.data = data,
		.len = len,
	};
	int ret;

	ret = callback(&input);
	if (ret < 0)
		return ret;
	if (!ret)
		return -EAGAIN;
	if ((size_t)ret > len)
		return -EPROTO;
	*frame_len = ret;
	return 0;
}

/**
 * datafs_bpf_build_request() - Invoke the request builder with isolated state.
 * @callback: provider request-builder callback
 * @ctx: private kernel request context
 *
 * Gives BPF a const input view and copies its output view back to @ctx.
 *
 * Return: callback result, validation failure, or -ENOMEM.
 */
int datafs_bpf_build_request(
	int (*callback)(struct tcpfs_build_request_ctx *ctx),
	struct tcpfs_ctx *ctx)
{
	struct tcpfs_build_request_ctx *call;
	int ret;

	call = kzalloc_obj(*call, GFP_KERNEL);
	if (!call)
		return -ENOMEM;
	call->input = ctx;
	call->output = *ctx;
	ret = callback(call);
	ret = tcpfs_bpf_validate_ctx(&call->output) ?: ret;
	*ctx = call->output;
	kfree(call);
	return ret;
}

/**
 * datafs_bpf_frame_tx() - Invoke the request framer with isolated state.
 * @callback: provider frame callback
 * @ctx: private kernel request context
 *
 * Gives BPF a const input view and copies its output view back to @ctx.
 *
 * Return: callback result, validation failure, or -ENOMEM.
 */
int datafs_bpf_frame_tx(int (*callback)(struct tcpfs_frame_tx_ctx *ctx),
			       struct tcpfs_ctx *ctx)
{
	struct tcpfs_frame_tx_ctx *call;
	int ret;

	call = kzalloc_obj(*call, GFP_KERNEL);
	if (!call)
		return -ENOMEM;
	call->input = ctx;
	call->output = *ctx;
	ret = callback(call);
	ret = tcpfs_bpf_validate_ctx(&call->output) ?: ret;
	*ctx = call->output;
	kfree(call);
	return ret;
}

/**
 * datafs_bpf_recv_response() - Classify a response with isolated state.
 * @callback: provider response-classifier callback
 * @ctx: private kernel receive context
 *
 * Gives BPF a const input view and copies its output view back to @ctx.
 *
 * Return: callback result, validation failure, or -ENOMEM.
 */
int datafs_bpf_recv_response(
	int (*callback)(struct tcpfs_recv_response_ctx *ctx),
	struct tcpfs_ctx *ctx)
{
	struct tcpfs_recv_response_ctx *call;
	int ret;

	call = kzalloc_obj(*call, GFP_KERNEL);
	if (!call)
		return -ENOMEM;
	call->input = ctx;
	call->output = *ctx;
	ret = callback(call);
	ret = tcpfs_bpf_validate_ctx(&call->output) ?: ret;
	*ctx = call->output;
	kfree(call);
	return ret;
}

/**
 * datafs_bpf_handle_response() - Decode a response with isolated state.
 * @callback: provider response-handler callback
 * @ctx: private kernel response context
 *
 * Gives BPF a const input view and copies its output view back to @ctx.
 *
 * Return: callback result, validation failure, or -ENOMEM.
 */
int datafs_bpf_handle_response(
	int (*callback)(struct tcpfs_handle_response_ctx *ctx),
	struct tcpfs_ctx *ctx)
{
	struct tcpfs_handle_response_ctx *call;
	int ret;

	call = kzalloc_obj(*call, GFP_KERNEL);
	if (!call)
		return -ENOMEM;
	call->input = ctx;
	call->output = *ctx;
	ret = callback(call);
	ret = tcpfs_bpf_validate_ctx(&call->output) ?: ret;
	*ctx = call->output;
	kfree(call);
	return ret;
}

/**
 * datafs_bpf_loan_socket() - Run a socket-loan callback with isolated state.
 * @callback: provider loan callback
 * @loan: kernel socket-loan state
 *
 * Return: callback result or -ENOMEM.
 */
int datafs_bpf_loan_socket(
	int (*callback)(struct tcpfs_loan_socket_ctx *ctx),
	struct tcpfs_socket_loan *loan)
{
	struct tcpfs_loan_socket_ctx *call;
	int ret;

	call = kzalloc_obj(*call, GFP_KERNEL);
	if (!call)
		return -ENOMEM;
	call->input = loan;
	call->output = *loan;
	ret = callback(call);
	*loan = call->output;
	kfree(call);
	return ret > 0 ? -EPROTO : ret;
}

/**
 * datafs_bpf_return_socket() - Run a socket-return callback with isolated state.
 * @callback: provider return callback
 * @loan: kernel socket-loan state
 */
void datafs_bpf_return_socket(
	void (*callback)(struct tcpfs_return_socket_ctx *ctx),
	struct tcpfs_socket_loan *loan)
{
	struct tcpfs_return_socket_ctx *call;

	call = kzalloc_obj(*call, GFP_KERNEL);
	if (!call)
		return;
	call->input = loan;
	call->output = *loan;
	callback(call);
	*loan = call->output;
	kfree(call);
}

/**
 * datafs_async_complete() - Finish a netfs subrequest from the transport.
 * @read: asynchronous read being completed
 * @ret: transport result, or zero when the result was decoded successfully
 * @copied: bytes copied into the netfs destination
 *
 * Converts the transport result into netfs subrequest state and drops the
 * private request allocation after netfs has taken ownership of completion.
 */
static void datafs_async_complete(struct datafs_async_read *read, int ret,
				  size_t copied)
{
	struct netfs_io_subrequest *subreq = read->subreq;
	struct netfs_io_request *rreq = subreq->rreq;

	if (copied) {
		subreq->transferred += copied;
		__set_bit(NETFS_SREQ_MADE_PROGRESS, &subreq->flags);
	}
	if (!ret && copied != read->ctx->len)
		ret = -EIO;
	subreq->error = ret < 0 ? ret : 0;
	if (rreq->origin != NETFS_UNBUFFERED_READ &&
	    rreq->origin != NETFS_DIO_READ)
		__set_bit(NETFS_SREQ_CLEAR_TAIL, &subreq->flags);
	if (subreq->start + subreq->transferred >= rreq->i_size)
		__set_bit(NETFS_SREQ_HIT_EOF, &subreq->flags);

	netfs_read_subreq_terminated(subreq);
	kfree(read->ctx);
	kfree(read);
}

/**
 * datafs_socket_open() - Create and connect a kernel TCP socket.
 * @sbi: superblock providing the endpoint, namespace, and timeouts
 * @sockp: returns the connected socket
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_socket_open(struct datafs_sb_info *sbi,
			      struct socket **sockp)
{
	struct datafs_server *server = &sbi->servers[0];
	struct socket *sock;
	int family;
	int ret;

	family = ((struct sockaddr *)&server->addr)->sa_family;
	ret = sock_create_kern(sbi->net_ns, family, SOCK_STREAM, IPPROTO_TCP,
			       &sock);
	if (ret)
		return ret;

	WRITE_ONCE(sock->sk->sk_rcvtimeo,
		   msecs_to_jiffies(sbi->opts.timeout_ms));
	WRITE_ONCE(sock->sk->sk_sndtimeo,
		   msecs_to_jiffies(sbi->opts.timeout_ms));

	ret = kernel_connect(sock, (struct sockaddr_unsized *)&server->addr,
			     server->addrlen, 0);
	if (ret) {
		sock_release(sock);
		return ret;
	}

	*sockp = sock;
	return 0;
}

/**
 * datafs_socket_reusable() - Whether a connection can rejoin the idle pool.
 * @sock: connection socket
 *
 * A connection is reusable only while its TCP state remains ESTABLISHED.
 */
static bool datafs_socket_reusable(const struct socket *sock)
{
	return sock && READ_ONCE(sock->sk->sk_state) == TCP_ESTABLISHED;
}

/**
 * datafs_connection_free() - Close a connection and release its allocation.
 * @conn: connection to release
 */
static void datafs_connection_free(struct datafs_connection *conn)
{
	if (conn->sock)
		sock_release(conn->sock);
	kfree(conn);
}

/**
 * datafs_connection_get() - Acquire a pooled connection with backpressure.
 * @sbi: superblock owning the pool
 * @connp: returns the acquired connection
 *
 * Takes a pool slot (downing the semaphore), reusing an idle serial connection
 * or opening a fresh one. The caller must return the connection with
 * datafs_connection_put().
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_connection_get(struct datafs_sb_info *sbi,
				 struct datafs_connection **connp)
{
	struct datafs_conn_pool *pool = sbi->conn_pool;
	struct datafs_connection *conn = NULL;
	u32 style = datafs_conn_style(sbi);
	int ret;

	if (style != TCPFS_CONN_NEW && style != TCPFS_CONN_SERIAL &&
	    style != TCPFS_CONN_OVERLAP)
		return -EINVAL;

	ret = down_interruptible(&pool->slots);
	if (ret)
		return ret;

	if (style == TCPFS_CONN_SERIAL) {
		mutex_lock(&pool->lock);
		if (!list_empty(&pool->idle)) {
			conn = list_first_entry(&pool->idle,
						struct datafs_connection, link);
			list_del_init(&conn->link);
		}
		mutex_unlock(&pool->lock);
	}

	if (!conn) {
		conn = kzalloc_obj(*conn, GFP_KERNEL);
		if (!conn) {
			ret = -ENOMEM;
			goto out_up;
		}
		INIT_LIST_HEAD(&conn->link);
	}

	if (!datafs_socket_reusable(conn->sock)) {
		if (conn->sock) {
			sock_release(conn->sock);
			conn->sock = NULL;
		}
		ret = datafs_socket_open(sbi, &conn->sock);
		if (ret)
			goto out_free;
	}

	*connp = conn;
	return 0;

out_free:
	datafs_connection_free(conn);
out_up:
	up(&pool->slots);
	return ret;
}

/**
 * datafs_connection_put() - Return a connection to the pool or discard it.
 * @sbi: superblock owning the pool
 * @conn: connection to return
 * @reusable: whether the connection is healthy enough to be pooled
 *
 * Returns a healthy serial connection to the idle list, otherwise frees it,
 * then releases the pool slot.
 */
static void datafs_connection_put(struct datafs_sb_info *sbi,
				  struct datafs_connection *conn,
				  bool reusable)
{
	struct datafs_conn_pool *pool = sbi->conn_pool;

	if (datafs_conn_style(sbi) == TCPFS_CONN_SERIAL && reusable &&
	    datafs_socket_reusable(conn->sock)) {
		mutex_lock(&pool->lock);
		list_add(&conn->link, &pool->idle);
		mutex_unlock(&pool->lock);
	} else {
		datafs_connection_free(conn);
	}

	up(&pool->slots);
}

/**
 * datafs_conn_pool_init() - Allocate the bounded transport pool.
 * @sbi: superblock receiving the pool
 *
 * Return: 0 on success, or a negative errno.
 */
int datafs_conn_pool_init(struct datafs_sb_info *sbi)
{
	struct datafs_conn_pool *pool;
	u32 style;
	int ret;

	if (!sbi || !sbi->ops || !sbi->opts.pool_size ||
	    sbi->opts.pool_size > DATAFS_MAX_CONNECTIONS)
		return -EINVAL;

	style = datafs_conn_style(sbi);
	if (style != TCPFS_CONN_NEW && style != TCPFS_CONN_SERIAL &&
	    style != TCPFS_CONN_OVERLAP)
		return -EINVAL;

	pool = kzalloc_obj(*pool, GFP_KERNEL);
	if (!pool)
		return -ENOMEM;

	sema_init(&pool->slots, sbi->opts.pool_size);
	mutex_init(&pool->lock);
	INIT_LIST_HEAD(&pool->idle);
	sbi->conn_pool = pool;
	ret = datafs_async_transport_init(sbi);
	if (ret) {
		sbi->conn_pool = NULL;
		kfree(pool);
	}
	return ret;
}

/**
 * datafs_conn_pool_destroy() - Close the transport pool and wake waiters.
 * @sbi: superblock whose pool is destroyed
 */
void datafs_conn_pool_destroy(struct datafs_sb_info *sbi)
{
	struct datafs_conn_pool *pool = sbi->conn_pool;
	struct datafs_connection *conn, *tmp;

	if (!pool)
		return;
	datafs_async_transport_destroy(sbi);

	list_for_each_entry_safe(conn, tmp, &pool->idle, link) {
		list_del(&conn->link);
		datafs_connection_free(conn);
	}
	sbi->conn_pool = NULL;
	kfree(pool);
}

/**
 * datafs_send() - Send an entire buffer, retrying short writes.
 * @sock: kernel socket
 * @buf: payload
 * @len: payload length
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_send(struct socket *sock, const void *buf, size_t len)
{
	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
	};
	struct kvec iov = {
		.iov_base = (void *)buf,
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

/**
 * datafs_recv() - Receive exactly @len bytes from @sock.
 * @sock: kernel socket
 * @buf: destination
 * @len: bytes to receive
 *
 * Return: 0 on success, or a negative errno (including -EPIPE on EOF).
 */
static int datafs_recv(struct socket *sock, void *buf, size_t len)
{
	struct msghdr msg = {};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = len,
	};

	return kernel_recvmsg(sock, &msg, &iov, 1, len, 0);
}

/**
 * datafs_send_nonblock() - Send as much of a buffer as the socket accepts.
 * @sock: socket carrying the exchange
 * @buf: transmit buffer
 * @len: total buffer length
 * @sent: bytes already transmitted, updated on success
 *
 * Uses nonblocking socket I/O so an asynchronous exchange can return to its
 * workqueue and wait for the socket's write-space wakeup.
 *
 * Return: 0 when the complete buffer was sent, -EAGAIN when more write space
 * is required, or another negative errno.
 */
static int datafs_send_nonblock(struct socket *sock, const void *buf,
				 size_t len, size_t *sent)
{
	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
	};
	struct kvec iov;
	int ret;

	while (*sent < len) {
		iov.iov_base = (void *)buf + *sent;
		iov.iov_len = len - *sent;
		ret = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK)
			return -EAGAIN;
		if (ret < 0)
			return ret;
		if (!ret)
			return -EPIPE;
		*sent += ret;
	}

	return 0;
}

/**
 * datafs_recv_nonblock() - Receive one bounded socket window without waiting.
 * @sock: socket carrying the exchange
 * @buf: receive destination
 * @len: maximum bytes to receive
 *
 * Return: positive bytes received, -EAGAIN when the socket has no data, or a
 * negative errno.
 */
static int datafs_recv_nonblock(struct socket *sock, void *buf, size_t len)
{
	struct msghdr msg = {};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = len,
	};
	int ret;

	ret = kernel_recvmsg(sock, &msg, &iov, 1, len, MSG_DONTWAIT);
	if (ret == -EAGAIN || ret == -EWOULDBLOCK)
		return -EAGAIN;
	return ret;
}

/**
 * datafs_async_socket_wake() - Resume transport work after socket progress.
 * @wait: socket wait entry embedded in the transport
 * @mode: wake mode
 * @sync: synchronous-wakeup hint
 * @key: event key
 *
 * Socket wakeups may arrive for either receive data or write space.  The
 * transport retries the operation in process context rather than doing
 * protocol work from the socket callback.
 *
 * Return: 0 to keep the wait entry installed.
 */
static int datafs_async_socket_wake(wait_queue_entry_t *wait,
				    unsigned int mode, int sync, void *key)
{
	struct datafs_async_transport *transport =
		container_of(wait, struct datafs_async_transport, socket_wait);

	(void)mode;
	(void)sync;
	(void)key;
	datafs_async_schedule(transport);
	return 0;
}

/**
 * datafs_async_timeout() - Resume transport work after its I/O deadline.
 * @timer: timeout timer embedded in the transport
 */
static void datafs_async_timeout(struct timer_list *timer)
{
	struct datafs_async_transport *transport =
		timer_container_of(transport, timer, timer);

	WRITE_ONCE(transport->timed_out, true);
	datafs_async_schedule(transport);
}

/**
 * datafs_async_arm() - Wait for the socket or transport timeout.
 * @transport: asynchronous transport waiting for I/O progress
 *
 * Installs one socket wait entry for the lifetime of the pending operation.
 * The immediate receive-queue check closes the race with data arriving before
 * the wait entry is linked.
 */
static void datafs_async_arm(struct datafs_async_transport *transport)
{
	struct sock *sk;

	mutex_lock(&transport->lock);
	if (transport->stopped || !transport->sock) {
		mutex_unlock(&transport->lock);
		return;
	}
	sk = transport->sock->sk;

	if (!transport->socket_waiting) {
		add_wait_queue(sk_sleep(sk), &transport->socket_wait);
		transport->socket_waiting = true;
	}
	mod_timer(&transport->timer,
		  jiffies + msecs_to_jiffies(transport->sbi->opts.timeout_ms));
	if (!skb_queue_empty_lockless(&sk->sk_receive_queue))
		datafs_async_schedule(transport);
	mutex_unlock(&transport->lock);
}

/**
 * datafs_async_disarm() - Remove socket and timeout notifications.
 * @transport: asynchronous transport being resumed or destroyed
 */
static void datafs_async_disarm(struct datafs_async_transport *transport)
{
	mutex_lock(&transport->lock);
	if (transport->socket_waiting) {
		if (transport->sock)
			remove_wait_queue(sk_sleep(transport->sock->sk),
					  &transport->socket_wait);
		transport->socket_waiting = false;
	}
	mutex_unlock(&transport->lock);
	timer_delete(&transport->timer);
}

/**
 * datafs_exchange() - Run one request/response exchange over @sock.
 * @sbi: superblock providing the provider callback table and mount argument
 * @sock: socket carrying the exchange
 * @ctx: callback context
 *
 * Invokes build_request/frame_tx, sends the request, then unframes and handles
 * the response, supporting CONTINUE-driven multi-frame exchanges.
 *
 * Return: 0 on success, -EAGAIN for an unsolicited response, or a negative
 * errno.
 */
static int datafs_exchange(struct datafs_sb_info *sbi, struct socket *sock,
			   struct tcpfs_ctx *ctx)
{
	const struct tcpfs_ops *ops = sbi->ops;
	size_t receive_limit;
	size_t frame_len;
	unsigned int exchanges = 0;
	int ret;
	int n;

	if (!ops || !ops->build_request || !ops->frame_tx ||
	    !ops->unframe_rx || !ops->handle_response)
		return -EOPNOTSUPP;
	if (ops->conn_style == TCPFS_CONN_OVERLAP)
		return -EOPNOTSUPP;
	if (ctx->path_len >= sizeof(ctx->path) ||
	    strnlen(ctx->path, sizeof(ctx->path)) != ctx->path_len ||
	    ctx->mount_arg_len >= sizeof(ctx->mount_arg) ||
	    strnlen(ctx->mount_arg, sizeof(ctx->mount_arg)) !=
		ctx->mount_arg_len)
		return -EINVAL;

	if (!ctx->mount_arg_len && sbi->opts.arg) {
		strscpy(ctx->mount_arg, sbi->opts.arg, sizeof(ctx->mount_arg));
		ctx->mount_arg_len = strlen(ctx->mount_arg);
	}

	ret = datafs_bpf_build_request(ops->build_request, ctx);
	if (ret)
		return ret;
	if (!ctx->payload_len || ctx->payload_len > sizeof(ctx->payload))
		return -EPROTO;

	ret = datafs_bpf_frame_tx(ops->frame_tx, ctx);
	if (ret)
		return ret;
	if (!ctx->payload_len || ctx->payload_len > sizeof(ctx->payload))
		return -EPROTO;

	receive_limit = min_t(size_t, sbi->opts.buf_size, sizeof(ctx->rx));

send_request:
	if (++exchanges > DATAFS_MAX_EXCHANGES)
		return -ELOOP;

	ret = datafs_send(sock, ctx->payload, ctx->payload_len);
	if (ret)
		return ret;

	ctx->rx_len = 0;
	for (;;) {
		size_t remaining = receive_limit - ctx->rx_len;

		if (!remaining)
			return -EMSGSIZE;
		n = datafs_recv(sock, ctx->rx + ctx->rx_len, remaining);
		if (n < 0)
			return n;
		if (!n)
			return -EPIPE;
		ctx->rx_len += n;

		ctx->frame_len = 0;
		memset(&ctx->result, 0, sizeof(ctx->result));
		ret = datafs_bpf_recv_response(ops->recv_response, ctx);
		if (ret == -EAGAIN) {
			if (ctx->rx_need > receive_limit)
				return -EMSGSIZE;
			continue;
		}
		if (ret)
			return ret;
		if (ctx->result.id && ctx->result.id != ctx->id)
			return -EPROTO;
		memset(&ctx->result, 0, sizeof(ctx->result));
		ret = datafs_bpf_unframe_rx(ops->unframe_rx, ctx->rx,
						ctx->rx_len, &frame_len);
		if (ret == -EAGAIN)
			continue;
		if (ret)
			return ret;
		ctx->frame_len = frame_len;

		ret = datafs_bpf_handle_response(ops->handle_response, ctx);
		if (ret == -EAGAIN) {
			if (ctx->rx_need > receive_limit)
				return -EMSGSIZE;
			continue;
		}
		if (ret)
			return ret;
		if (ctx->result.type != TCPFS_RESULT_CONTINUE)
			break;
		if (ctx->frame_len != ctx->rx_len)
			return -EPROTO;

		ret = datafs_bpf_frame_tx(ops->frame_tx, ctx);
		if (ret)
			return ret;
		if (!ctx->payload_len || ctx->payload_len > sizeof(ctx->payload))
			return -EPROTO;
		goto send_request;
	}

	if (ctx->result.id && ctx->result.id != ctx->id) {
		return -EAGAIN;
	}
	if (ctx->result.error > 0)
		return -EPROTO;

	return 0;
}

/**
 * datafs_call() - Execute one provider operation with a pooled connection.
 * @sbi: superblock
 * @ctx: callback context to populate
 *
 * Return: 0 on success, or a negative errno.
 */
int datafs_call(struct datafs_sb_info *sbi, struct tcpfs_ctx *ctx)
{
	struct datafs_connection *conn;
	int ret;

	if (!sbi || !ctx)
		return -EINVAL;

	ret = datafs_connection_get(sbi, &conn);
	if (ret)
		return ret;

	ret = datafs_exchange(sbi, conn->sock, ctx);
	datafs_connection_put(sbi, conn, !ret);
	return ret;
}

/**
 * datafs_validate_read_result() - Validate a read result's framing metadata.
 * @ctx: context with the result to validate
 *
 * Return: 0 when valid, or -EPROTO.
 */
static int datafs_validate_read_result(const struct tcpfs_ctx *ctx)
{
	const struct tcpfs_rx_run *run = &ctx->result.rx_run;
	size_t available;

	if (ctx->result.payload_len > ctx->len)
		return -EPROTO;
	if (ctx->result.offset && ctx->result.offset != ctx->offset)
		return -EPROTO;
	if (!run->data_len)
		return 0;
	if (run->wire_len > SIZE_MAX || run->rx_offset > ctx->rx_len ||
	    run->wire_len < run->data_len)
		return -EPROTO;

	available = ctx->rx_len - run->rx_offset;
	available = min_t(u64, available, run->wire_len);
	available = min_t(u64, available, run->data_len);
	return ctx->result.payload_len == available ? 0 : -EPROTO;
}

/**
 * datafs_copy_initial_data() - Copy file data already in the receive window.
 * @ctx: context with the result and its scheduled data
 * @to: destination iterator
 * @copied: accumulated copied count (updated)
 *
 * Return: 0 on success, or -EPROTO/-EFAULT.
 */
static int datafs_copy_initial_data(struct tcpfs_ctx *ctx,
				    struct iov_iter *to, size_t *copied)
{
	const void *payload = ctx->result.payload;
	size_t len = min_t(size_t, ctx->result.payload_len, ctx->len);
	size_t available;
	size_t done;

	if (ctx->result.payload_len > sizeof(ctx->result.payload))
		return -EPROTO;
	if (ctx->result.rx_run.data_len) {
		available = ctx->rx_len - ctx->result.rx_run.rx_offset;
		available = min_t(u64, available,
				  ctx->result.rx_run.wire_len);
		available = min_t(u64, available,
				  ctx->result.rx_run.data_len);
		if (ctx->result.payload_len != available)
			return -EPROTO;
		payload = ctx->rx + ctx->result.rx_run.rx_offset;
	}

	done = copy_to_iter(payload, len, to);
	*copied += done;
	return done == len ? 0 : -EFAULT;
}

/**
 * datafs_read_body() - Stream the remainder of a read result into @to.
 * @sock: socket to stream from
 * @ctx: validated result context
 * @to: destination iterator
 * @copied: accumulated copied count (updated)
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_read_body(struct socket *sock, struct tcpfs_ctx *ctx,
			    struct iov_iter *to, size_t *copied)
{
	size_t target = ctx->result.rx_run.data_len;
	size_t wire_target = ctx->result.rx_run.wire_len;
	size_t wire_consumed;
	size_t buf_len = min_t(size_t, PAGE_SIZE, TCPFS_PAYLOAD_MAX);
	void *buf;
	int ret = 0;

	if (!ctx->result.rx_run.data_len)
		return 0;
	if (ctx->result.rx_run.rx_offset > ctx->rx_len ||
	    wire_target < ctx->result.rx_run.data_len)
		return -EPROTO;

	wire_consumed = ctx->rx_len - ctx->result.rx_run.rx_offset;
	wire_consumed = min(wire_consumed, wire_target);
	if (wire_consumed >= wire_target)
		return 0;

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	while (wire_consumed < wire_target) {
		size_t want = min(buf_len, wire_target - wire_consumed);
		size_t data_len;
		size_t done;

		ret = datafs_recv(sock, buf, want);
		if (ret < 0)
			break;
		if (!ret) {
			ret = -EPIPE;
			break;
		}

		if (*copied < target)
			data_len = min_t(size_t, ret, target - *copied);
		else
			data_len = 0;
		done = copy_to_iter(buf, data_len, to);
		*copied += done;
		wire_consumed += ret;
		if (done != data_len) {
			ret = -EFAULT;
			break;
		}
	}

	kfree(buf);
	return ret < 0 ? ret : 0;
}

/**
 * datafs_read_to_iter() - Read one file extent into a netfs iterator.
 * @sbi: superblock
 * @path: root-relative object path
 * @path_len: length of @path
 * @ino: remote inode number
 * @offset: byte offset
 * @len: byte length to read
 * @to: destination iterator
 *
 * Issues one or more READ callbacks over the transport pool and copies the
 * returned file bytes into @to.
 *
 * Return: the number of bytes copied, or a negative errno.
 */
ssize_t datafs_read_to_iter(struct datafs_sb_info *sbi, const char *path,
			    u32 path_len, u64 ino, u64 offset, size_t len,
			    struct iov_iter *to)
{
	struct tcpfs_ctx *ctx;
	struct datafs_connection *conn = NULL;
	size_t copied = 0;
	size_t actual_path_len;
	size_t chunk_copied;
	ssize_t ret = 0;
	bool reusable = true;
	bool serial;

	if (!len)
		return 0;
	if (!sbi || !to || len > MAX_RW_COUNT || len > iov_iter_count(to))
		return -EINVAL;
	if (len > U64_MAX - offset)
		return -EOVERFLOW;
	path = path ?: "";
	actual_path_len = strnlen(path, TCPFS_PATH_MAX);
	if (actual_path_len == TCPFS_PATH_MAX)
		return -ENAMETOOLONG;
	if (path_len != actual_path_len)
		return -EINVAL;

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	serial = datafs_conn_style(sbi) == TCPFS_CONN_SERIAL;
	if (serial) {
		ret = datafs_connection_get(sbi, &conn);
		if (ret)
			goto out;
	}

	while (copied < len) {
		memset(ctx, 0, sizeof(*ctx));
		ctx->op = TCPFS_OP_READ;
		ctx->ino = ino;
		ctx->id = atomic64_inc_return(&sbi->next_id);
		ctx->offset = offset + copied;
		ctx->len = len - copied;
		memcpy(ctx->path, path, path_len + 1);
		ctx->path_len = path_len;
		chunk_copied = 0;

		if (!serial) {
			ret = datafs_connection_get(sbi, &conn);
			if (ret)
				break;
		}

		ret = datafs_exchange(sbi, conn->sock, ctx);
		reusable = !ret;
		if (!ret)
			ret = ctx->result.error;
		if (!ret && ctx->result.type != TCPFS_RESULT_DATA) {
			ret = -EIO;
			reusable = false;
		}
		if (!ret) {
			ret = datafs_validate_read_result(ctx);
			if (ret)
				reusable = false;
		}
		if (!ret) {
			ret = datafs_copy_initial_data(ctx, to, &chunk_copied);
			if (ret)
				reusable = false;
		}
		if (!ret) {
			ret = datafs_read_body(conn->sock, ctx, to,
					       &chunk_copied);
			if (ret)
				reusable = false;
		}

		if (!serial) {
			datafs_connection_put(sbi, conn, reusable);
			conn = NULL;
		}
		copied += chunk_copied;
		if (ret || !chunk_copied)
			break;
	}

	if (conn)
		datafs_connection_put(sbi, conn, reusable);
	if (copied)
		ret = copied;
out:
	kfree(ctx);
	return ret;
}

/**
 * datafs_async_prepare() - Build one request for the shared read socket.
 * @read: request being prepared
 *
 * Builds the provider payload once before it enters the pipelined queue.  The
 * request context remains private to the request so a response can be decoded
 * after another request has used the same socket.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_async_prepare(struct datafs_async_read *read)
{
	struct datafs_sb_info *sbi = read->transport->sbi;
	struct tcpfs_ctx *ctx = read->ctx;
	const struct tcpfs_ops *ops = sbi->ops;
	int ret;

	if (!ops->build_request || !ops->frame_tx || !ops->recv_response ||
	    !ops->unframe_rx || !ops->handle_response)
		return -EOPNOTSUPP;
	if (!ctx->mount_arg_len && sbi->opts.arg) {
		ret = strscpy(ctx->mount_arg, sbi->opts.arg,
			      sizeof(ctx->mount_arg));
		if (ret < 0)
			return -ENAMETOOLONG;
		ctx->mount_arg_len = ret;
	}
	ret = datafs_bpf_build_request(ops->build_request, ctx);
	if (ret)
		return ret;
	if (!ctx->payload_len || ctx->payload_len > sizeof(ctx->payload))
		return -EPROTO;
	ret = datafs_bpf_frame_tx(ops->frame_tx, ctx);
	if (ret)
		return ret;
	if (!ctx->payload_len || ctx->payload_len > sizeof(ctx->payload))
		return -EPROTO;
	return 0;
}

/**
 * datafs_async_receive_more() - Extend the shared receive window.
 * @transport: asynchronous transport
 * @need: minimum receive-window length requested by BPF
 *
 * Reads exactly the additional amount requested by the provider.  Capping the
 * receive length prevents a pipelined response from being consumed along with
 * the body of the response currently being dispatched.
 *
 * Return: 0 on progress, or a negative errno.
 */
static int datafs_async_receive_more(struct datafs_async_transport *transport,
					     size_t need)
{
	size_t limit = min_t(size_t, transport->sbi->opts.buf_size,
					    TCPFS_PAYLOAD_MAX);
	int ret;

	if (need <= transport->rx_len)
		need = transport->rx_len + 1;
	if (need > limit)
		return -EMSGSIZE;
	ret = datafs_recv_nonblock(transport->sock,
					   transport->rx + transport->rx_len,
					   need - transport->rx_len);
	if (ret == -EAGAIN)
		return ret;
	if (ret <= 0)
		return ret ?: -EPIPE;
	transport->rx_len += ret;
	return 0;
}

/**
 * datafs_async_probe() - Ask BPF to classify the receive window.
 * @transport: asynchronous transport
 * @probe: temporary context receiving the classification result
 *
 * The probe has no request identity.  BPF returns the wire request id in
 * result.id, allowing the kernel to select a pending request without an
 * unsolicited callback or a socket-global ordering assumption.
 *
 * Return: callback result, including -EAGAIN when more bytes are needed.
 */
static int datafs_async_probe(struct datafs_async_transport *transport,
				      struct tcpfs_ctx *probe)
{
	const struct tcpfs_ops *ops = transport->sbi->ops;

	memset(probe, 0, sizeof(*probe));
	probe->rx_len = transport->rx_len;
	memcpy(probe->rx, transport->rx, transport->rx_len);
	return datafs_bpf_recv_response(ops->recv_response, probe);
}

/**
 * datafs_async_find_request() - Find the request named by a response.
 * @transport: asynchronous transport
 * @id: provider response identity, or zero for ordered protocols
 *
 * A zero identity is reserved for protocols such as HTTP/1.1 whose response
 * stream is ordered but does not echo an application request id.
 *
 * Return: matching pending request, or NULL for an invalid response.
 */
static struct datafs_async_read *
datafs_async_find_request(struct datafs_async_transport *transport, u64 id)
{
	struct datafs_async_read *read;

	if (!id)
		return list_first_entry_or_null(&transport->pending,
					       struct datafs_async_read, link);
	list_for_each_entry(read, &transport->pending, link)
		if (read->ctx->id == id)
			return read;
	return NULL;
}

/**
 * datafs_async_dispatch() - Decode and complete one pipelined response.
 * @transport: asynchronous transport
 * @read: request selected by the receive callback
 * @copied: bytes copied into the request iterator (updated)
 *
 * Copies the bounded receive window into the request context, lets the
 * provider decode it, and streams a file-data body before allowing the next
 * response to be classified.  Continuation responses are sent on the same
 * socket and remain pending.
 *
 * Return: 1 when the request continues, 0 when it completed, or a negative
 * errno.
 */
static int datafs_async_dispatch(struct datafs_async_transport *transport,
					 struct datafs_async_read *read,
					 size_t *copied)
{
	struct tcpfs_ctx *ctx = read->ctx;
	const struct tcpfs_ops *ops = transport->sbi->ops;
	size_t frame_len;
	int ret;

	memset(ctx->rx, 0, sizeof(ctx->rx));
	memcpy(ctx->rx, transport->rx, transport->rx_len);
	ctx->rx_len = transport->rx_len;
	for (;;) {
		ctx->frame_len = 0;
		ctx->rx_need = 0;
		memset(&ctx->result, 0, sizeof(ctx->result));
		ret = datafs_bpf_unframe_rx(ops->unframe_rx, ctx->rx,
						ctx->rx_len, &frame_len);
		if (ret == -EAGAIN) {
			ret = datafs_async_receive_more(transport, 0);
			if (ret)
				return ret;
			memcpy(ctx->rx, transport->rx, transport->rx_len);
			ctx->rx_len = transport->rx_len;
			continue;
		}
		if (ret)
			return ret;
		ctx->frame_len = frame_len;

		ret = datafs_bpf_handle_response(ops->handle_response, ctx);
		if (ret == -EAGAIN) {
			ret = datafs_async_receive_more(transport, ctx->rx_need);
			if (ret)
				return ret;
			memcpy(ctx->rx, transport->rx, transport->rx_len);
			ctx->rx_len = transport->rx_len;
			continue;
		}
		if (ret)
			return ret;
		if (ctx->result.error)
			return ctx->result.error < 0 ? ctx->result.error : -EPROTO;
		if (ctx->result.type == TCPFS_RESULT_CONTINUE) {
			if (ctx->frame_len != transport->rx_len)
				return -EPROTO;
			if (++read->exchanges > DATAFS_MAX_EXCHANGES)
				return -ELOOP;
			ret = datafs_bpf_frame_tx(ops->frame_tx, ctx);
			if (ret)
				return ret;
			if (!ctx->payload_len ||
			    ctx->payload_len > sizeof(ctx->payload))
				return -EPROTO;
			read->sent = 0;
			transport->rx_len = 0;
			ret = datafs_send_nonblock(transport->sock, ctx->payload,
						   ctx->payload_len,
						   &read->sent);
			if (ret)
				return ret;
			return 1;
		}
		if (ctx->result.type != TCPFS_RESULT_DATA)
			return -EPROTO;
		ret = datafs_validate_read_result(ctx);
		if (ret)
			return ret;
		ret = datafs_copy_initial_data(ctx, &read->subreq->io_iter,
					       copied);
		if (ret)
			return ret;
		ret = datafs_read_body(transport->sock, ctx,
				       &read->subreq->io_iter, copied);
		if (ret)
			return ret;
		transport->rx_len = 0;
		return 0;
	}
}

/**
 * datafs_async_fail_pending() - Fail all requests after socket loss.
 * @transport: asynchronous transport
 * @error: error delivered to each netfs subrequest
 */
static void datafs_async_fail_pending(struct datafs_async_transport *transport,
					      int error)
{
	LIST_HEAD(failed);
	struct datafs_async_read *read, *tmp;

	mutex_lock(&transport->lock);
	list_splice_tail_init(&transport->pending, &failed);
	list_splice_tail_init(&transport->queued, &failed);
	mutex_unlock(&transport->lock);

	list_for_each_entry_safe(read, tmp, &failed, link) {
		list_del_init(&read->link);
		datafs_async_complete(read, error, 0);
	}
}

/**
 * datafs_async_worker_done() - Hand off an exiting worker to new submissions.
 * @transport: asynchronous transport whose worker is exiting
 *
 * Submission and worker exit serialize through the transport lock.  A request
 * queued before the active flag is cleared is rescheduled here; one queued
 * afterwards observes the clear flag and schedules its own worker.
 */
static void datafs_async_worker_done(struct datafs_async_transport *transport)
{
	bool reschedule;

	mutex_lock(&transport->lock);
	reschedule = !transport->stopped && !list_empty(&transport->queued);
	if (!reschedule)
		transport->worker_active = false;
	mutex_unlock(&transport->lock);
	if (reschedule)
		datafs_async_schedule(transport);
}

/**
 * datafs_async_worker() - Drive the shared pipelined read connection.
 * @work: asynchronous transport work item
 *
 * Overlap-capable providers send every queued request before receiving.  Other
 * providers finish the pending head before advancing; NEW providers also
 * reopen the socket between operations.  The receive callback identifies each
 * response when unrelated operations may be in flight on one TCP connection.
 */
static void datafs_async_worker(struct work_struct *work)
{
	struct datafs_async_transport *transport =
		container_of(to_delayed_work(work), struct datafs_async_transport,
			     work);
	struct datafs_async_read *read;
	struct tcpfs_ctx *probe;
	u32 conn_style;
	bool serial;
	int ret;

	datafs_async_disarm(transport);
	conn_style = datafs_conn_style(transport->sbi);
	serial = conn_style != TCPFS_CONN_OVERLAP;
	probe = kzalloc(sizeof(*probe), GFP_KERNEL);
	if (!probe) {
		datafs_async_fail_pending(transport, -ENOMEM);
		datafs_async_worker_done(transport);
		return;
	}
	if (!transport->sock) {
		WRITE_ONCE(transport->timed_out, false);
		ret = datafs_socket_open(transport->sbi, &transport->sock);
		if (ret)
			goto fail;
	}

	for (;;) {
		mutex_lock(&transport->lock);
		if (transport->stopped) {
			mutex_unlock(&transport->lock);
			ret = -ESHUTDOWN;
			goto fail;
		}
		if (transport->timed_out) {
			mutex_unlock(&transport->lock);
			ret = -ETIMEDOUT;
			goto fail;
		}
		list_splice_tail_init(&transport->queued, &transport->pending);
		if (list_empty(&transport->pending)) {
			transport->worker_active = false;
			mutex_unlock(&transport->lock);
			break;
		}
		mutex_unlock(&transport->lock);
		if (!transport->sock) {
			WRITE_ONCE(transport->timed_out, false);
			ret = datafs_socket_open(transport->sbi,
						 &transport->sock);
			if (ret)
				goto fail;
		}

		list_for_each_entry(read, &transport->pending, link) {
			if (serial &&
			    read != list_first_entry(&transport->pending,
						     struct datafs_async_read, link))
				break;
			if (read->prepared &&
			    read->sent == read->ctx->payload_len)
				continue;
			if (!read->prepared) {
				ret = datafs_async_prepare(read);
				if (ret)
					goto fail;
				read->prepared = true;
				read->exchanges = 1;
			}
			ret = datafs_send_nonblock(transport->sock, read->ctx->payload,
						   read->ctx->payload_len,
						   &read->sent);
			if (ret == -EAGAIN) {
				datafs_async_arm(transport);
				goto out;
			}
			if (ret)
				goto fail;
		}

		for (;;) {
			ret = datafs_async_probe(transport, probe);
			if (ret == -EAGAIN) {
				ret = datafs_async_receive_more(transport,
								probe->rx_need);
				if (ret == -EAGAIN) {
					datafs_async_arm(transport);
					goto out;
				}
				if (ret)
					goto fail;
				continue;
			}
			if (ret)
				goto fail;
			read = datafs_async_find_request(transport,
							 probe->result.id);
			if (!read)
				goto fail_proto;
			ret = datafs_async_dispatch(transport, read, &read->copied);
			if (ret == 1)
				continue;
			if (ret == -EAGAIN) {
				datafs_async_arm(transport);
				goto out;
			}
			if (ret)
				goto fail;
			list_del_init(&read->link);
			datafs_async_complete(read, 0, read->copied);
			if (conn_style == TCPFS_CONN_NEW && transport->sock) {
				sock_release(transport->sock);
				transport->sock = NULL;
			}
			break;
		}
	}

out:
	kfree(probe);
	return;

fail_proto:
	ret = -EPROTO;
fail:
	datafs_async_disarm(transport);
	datafs_async_fail_pending(transport, ret);
	if (transport->sock) {
		sock_release(transport->sock);
		transport->sock = NULL;
	}
	datafs_async_worker_done(transport);
	kfree(probe);
	return;

}

/**
 * datafs_async_transport_init() - Allocate the per-mount read transport.
 * @sbi: superblock owning the transport
 *
 * The socket is opened lazily by the worker so mount and read submission stay
 * independent of endpoint availability.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_async_transport_init(struct datafs_sb_info *sbi)
{
	struct datafs_async_transport *transport;

	transport = kzalloc(sizeof(*transport), GFP_KERNEL);
	if (!transport)
		return -ENOMEM;
	transport->rx = kmalloc(min_t(size_t, sbi->opts.buf_size,
					     TCPFS_PAYLOAD_MAX), GFP_KERNEL);
	if (!transport->rx) {
		kfree(transport);
		return -ENOMEM;
	}
	transport->sbi = sbi;
	mutex_init(&transport->lock);
	INIT_LIST_HEAD(&transport->queued);
	INIT_LIST_HEAD(&transport->pending);
	INIT_DELAYED_WORK(&transport->work, datafs_async_worker);
	init_waitqueue_func_entry(&transport->socket_wait,
					 datafs_async_socket_wake);
	timer_setup(&transport->timer, datafs_async_timeout, 0);
	sbi->async_transport = transport;
	return 0;
}

/**
 * datafs_async_transport_destroy() - Stop and free the read transport.
 * @sbi: superblock whose transport is being destroyed
 */
static void datafs_async_transport_destroy(struct datafs_sb_info *sbi)
{
	struct datafs_async_transport *transport = sbi->async_transport;

	if (!transport)
		return;
	mutex_lock(&transport->lock);
	transport->stopped = true;
	mutex_unlock(&transport->lock);
	datafs_async_disarm(transport);
	timer_shutdown_sync(&transport->timer);
	cancel_delayed_work_sync(&transport->work);
	datafs_async_fail_pending(transport, -ESHUTDOWN);
	if (transport->sock)
		sock_release(transport->sock);
	kfree(transport->rx);
	kfree(transport);
	sbi->async_transport = NULL;
}

/**
 * datafs_read_async() - Queue a netfs read on the shared transport.
 * @sbi: superblock
 * @path: root-relative object path
 * @path_len: length of @path
 * @ino: remote inode number
 * @offset: byte offset
 * @len: byte length to read
 * @subreq: netfs subrequest to complete asynchronously
 *
 * The request context and path metadata remain allocated until the response
 * is decoded.  The caller must terminate @subreq itself when this function
 * returns an error.
 *
 * Return: 0 after queueing, or a negative errno.
 */
int datafs_read_async(struct datafs_sb_info *sbi, const char *path,
			      u32 path_len, u64 ino, u64 offset, size_t len,
			      struct netfs_io_subrequest *subreq)
{
	struct datafs_async_transport *transport = sbi->async_transport;
	struct datafs_async_read *read;
	bool schedule;

	if (!transport || !subreq || !len || len > MAX_RW_COUNT ||
	    path_len >= TCPFS_PATH_MAX || !path ||
	    strnlen(path, TCPFS_PATH_MAX) != path_len ||
	    offset > U64_MAX - len)
		return -EINVAL;
	read = kzalloc(sizeof(*read), GFP_KERNEL);
	if (!read)
		return -ENOMEM;
	read->ctx = kzalloc(sizeof(*read->ctx), GFP_KERNEL);
	if (!read->ctx) {
		kfree(read);
		return -ENOMEM;
	}
	read->transport = transport;
	read->subreq = subreq;
	read->ctx->id = atomic64_inc_return(&sbi->next_id);
	read->ctx->ino = ino;
	read->ctx->offset = offset;
	read->ctx->len = len;
	read->ctx->op = TCPFS_OP_READ;
	read->ctx->path_len = path_len;
	memcpy(read->ctx->path, path, path_len + 1);
	INIT_LIST_HEAD(&read->link);

	mutex_lock(&transport->lock);
	if (transport->stopped) {
		mutex_unlock(&transport->lock);
		kfree(read->ctx);
		kfree(read);
		return -ESHUTDOWN;
	}
	list_add_tail(&read->link, &transport->queued);
	schedule = !transport->worker_active;
	transport->worker_active = true;
	mutex_unlock(&transport->lock);
	if (schedule)
		datafs_async_schedule(transport);
	return 0;
}
