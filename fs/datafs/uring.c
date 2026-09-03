// SPDX-License-Identifier: GPL-2.0
#include <linux/dma-buf.h>
#include <linux/io_uring/cmd.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/uio.h>
#include <linux/xarray.h>
#include <net/devmem.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <uapi/linux/datafs.h>

#include "datafs.h"

#define DATAFS_DEVMEM_SEGS	32

struct datafs_uring_pdu {
	/* Protects publication against cancellation and final completion. */
	spinlock_t lock;
	struct datafs_devmem_read *read;
};

struct datafs_devmem_loan {
	refcount_t refs;
	struct datafs_sb_info *sbi;
	struct tcpfs_socket_loan bpf;
	struct dma_buf *dmabuf;
	u32 dmabuf_id;
	u16 id;
	/* Serializes token validation, socket return, and tracking updates. */
	struct mutex token_lock;
	struct xarray tokens;
	atomic_t outstanding;
	atomic_t releasing;
	bool command_done;
	bool registered;
};

struct datafs_devmem_seg {
	struct dmabuf_cmsg cmsg;
	bool dmabuf;
	bool header_copied;
};

struct datafs_devmem_read {
	struct list_head wait_link;
	struct io_uring_cmd *cmd;
	struct datafs_sb_info *sbi;
	struct datafs_devmem_loan *loan;
	struct tcpfs_ctx *ctx;
	wait_queue_entry_t socket_wait;
	struct timer_list timer;
	refcount_t refs;
	/* Serializes a published copy request with its response. */
	struct mutex copy_lock;
	atomic_t scheduled;
	atomic_t pending;
	bool armed;
	bool waiting;
	bool socket_waiting;
	bool socket_retry;
	bool pbuf_owned;
	bool copy_pending;
	bool header_parse_pending;
	bool request_ready;
	bool response_ready;
	bool initial_posted;
	bool cancelled;
	bool timed_out;
	bool done;
	u16 host_group;
	u32 dmabuf_id;
	u32 flags;
	size_t request_len;
	size_t sent;
	size_t copied;
	size_t target_len;
	size_t wire_len;
	size_t wire_done;
	int final_ret;
	int copy_error;
	u32 copy_key;
	size_t copy_len;
	u8 *header_linear;
	size_t header_linear_len;
	size_t header_linear_pos;
	unsigned int header_nr_segs;
	unsigned int header_seg;
	struct datafs_devmem_seg header_segs[DATAFS_DEVMEM_SEGS];
};

static void datafs_devmem_schedule(struct datafs_devmem_read *read);
static void datafs_read_put(struct datafs_devmem_read *read);

/**
 * datafs_loan_put() - Drop a socket-loan reference, freeing it at zero.
 * @loan: loan to reference-drop
 *
 * When the last reference is released the token registry is destroyed and the
 * loan object freed.
 */
static void datafs_loan_put(struct datafs_devmem_loan *loan)
{
	if (refcount_dec_and_test(&loan->refs)) {
		xa_destroy(&loan->tokens);
		kfree(loan);
	}
}

/**
 * datafs_wake_loan_waiter() - Wake the oldest socket-loan waiter.
 * @sbi: superblock whose waiter list is serviced
 *
 * Pops one waiting command (skipping cancelled ones) and schedules it to
 * retry the loan in task context.
 */
static void datafs_wake_loan_waiter(struct datafs_sb_info *sbi)
{
	struct datafs_devmem_read *read = NULL;

	spin_lock(&sbi->loan_lock);
	while (!list_empty(&sbi->loan_waiters)) {
		read = list_first_entry(&sbi->loan_waiters,
					struct datafs_devmem_read, wait_link);
		list_del_init(&read->wait_link);
		read->waiting = false;
		if (READ_ONCE(read->cancelled))
			continue;
		refcount_inc(&read->refs);
		read->socket_retry = false;
		break;
	}
	spin_unlock(&sbi->loan_lock);
	if (read) {
		datafs_devmem_schedule(read);
		datafs_read_put(read);
	}
}

/**
 * datafs_release_loan() - Return a loaned socket and drop the loan ID.
 * @loan: loan whose socket is returned
 *
 * Returns the provider socket through return_socket(), releases the dma-buf
 * reference, and removes the mount-visible loan registry entry. Safe to call
 * exactly once per loan (releasing is atomic).
 */
static void datafs_release_loan(struct datafs_devmem_loan *loan)
{
	struct datafs_sb_info *sbi = loan->sbi;
	bool registered;

	if (atomic_cmpxchg(&loan->releasing, 0, 1))
		return;

	if (loan->bpf.sk) {
		loan->bpf.socket_returned = 0;
		datafs_bpf_return_socket(sbi->ops->return_socket, &loan->bpf);
		if (!loan->bpf.socket_returned)
			pr_warn_ratelimited("datafs: provider failed to return socket %u\n",
					    loan->bpf.socket_key);
		sock_put(loan->bpf.sk);
		loan->bpf.sk = NULL;
	}
	if (loan->dmabuf) {
		dma_buf_put(loan->dmabuf);
		loan->dmabuf = NULL;
	}

	registered = loan->registered;
	if (registered) {
		loan->registered = false;
		if (xa_erase(&sbi->devmem_loans, loan->id) != loan)
			WARN_ON_ONCE(1);
		datafs_loan_put(loan);
	}
	datafs_wake_loan_waiter(sbi);
}

/**
 * datafs_release_loan_if_idle() - Release a loan once it is idle and done.
 * @loan: loan to release
 *
 * Releases the loan only when its command completed and every published token
 * has been returned by userspace.
 */
static void datafs_release_loan_if_idle(struct datafs_devmem_loan *loan)
{
	if (READ_ONCE(loan->command_done) &&
	    !atomic_read(&loan->outstanding))
		datafs_release_loan(loan);
}

/**
 * datafs_record_token() - Record a published dma-buf token for a loan.
 * @loan: loan the token is published under
 * @token_id: published token to track
 *
 * Adds @token_id to the loan's outstanding-token registry.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_record_token(struct datafs_devmem_loan *loan, u32 token_id)
{
	int ret;

	mutex_lock(&loan->token_lock);
	ret = xa_insert(&loan->tokens, token_id, xa_mk_value(1), GFP_KERNEL);
	if (!ret)
		atomic_inc(&loan->outstanding);
	mutex_unlock(&loan->token_lock);
	return ret;
}

/**
 * __datafs_forget_tokens() - Remove a token range with the lock held.
 * @loan: loan whose token registry is updated
 * @token: first token
 * @count: number of consecutive tokens starting at @token
 *
 * Caller must hold loan->token_lock.
 */
static void __datafs_forget_tokens(struct datafs_devmem_loan *loan, u32 token,
				   u32 count)
{
	u32 i;

	for (i = 0; i < count; i++)
		if (xa_erase(&loan->tokens, token + i))
			atomic_dec(&loan->outstanding);
}

/**
 * datafs_forget_tokens() - Forget a published token range.
 * @loan: loan whose tokens are returned
 * @token: first token
 * @count: number of consecutive tokens
 */
static void datafs_forget_tokens(struct datafs_devmem_loan *loan, u32 token,
				 u32 count)
{
	mutex_lock(&loan->token_lock);
	__datafs_forget_tokens(loan, token, count);
	mutex_unlock(&loan->token_lock);
}

/**
 * datafs_has_tokens() - Whether a consecutive token range is still outstanding.
 * @loan: loan whose registry is checked
 * @token: first token
 * @count: number of tokens in @range
 *
 * Return: true when every token in the range is present in the loan registry.
 */
static bool datafs_has_tokens(struct datafs_devmem_loan *loan, u32 token,
			      u32 count)
{
	u32 i;

	for (i = 0; i < count; i++)
		if (!xa_load(&loan->tokens, token + i))
			return false;
	return true;
}

/**
 * datafs_return_token() - Return published tokens to the devmem allocator.
 * @loan: loan owning the tokens
 * @token: first token
 * @count: number of consecutive tokens
 *
 * Validates the range against the loan's outstanding registry, returns the
 * fragments through sock_devmem_dontneed(), and forgets them.
 *
 * Return: the number returned, or a negative errno.
 */
static int datafs_return_token(struct datafs_devmem_loan *loan, u32 token,
			       u32 count)
{
	struct dmabuf_token range = {
		.token_start = token,
		.token_count = count,
	};
	int ret;

	if (!count || token > U32_MAX - count + 1)
		return -EINVAL;
	mutex_lock(&loan->token_lock);
	if (!datafs_has_tokens(loan, token, count)) {
		ret = -ENOENT;
		goto out_unlock;
	}
	ret = sock_devmem_dontneed(loan->bpf.sk, &range, 1);
	if (ret == count)
		__datafs_forget_tokens(loan, token, count);
out_unlock:
	mutex_unlock(&loan->token_lock);
	return ret;
}

/**
 * datafs_recycle_token() - Return a single unpublished token immediately.
 * @loan: loan the token was received under
 * @token: token to return
 *
 * Return: the number of fragments returned (1), or a negative errno.
 */
static int datafs_recycle_token(struct datafs_devmem_loan *loan, u32 token)
{
	struct dmabuf_token range = {
		.token_start = token,
		.token_count = 1,
	};

	return sock_devmem_dontneed(loan->bpf.sk, &range, 1);
}

/**
 * datafs_pdu_get() - Take a stable ref to the command state in a PDU.
 * @pdu: uring command payload
 *
 * Return: the referenced read state, or NULL when the PDU is no longer owned.
 */
static struct datafs_devmem_read *
datafs_pdu_get(struct datafs_uring_pdu *pdu)
{
	struct datafs_devmem_read *read;

	spin_lock(&pdu->lock);
	read = pdu->read;
	if (read)
		refcount_inc(&read->refs);
	spin_unlock(&pdu->lock);
	return read;
}

/**
 * datafs_pdu_clear() - Clear the PDU if it still references @read.
 * @pdu: uring command payload
 * @read: expected command state
 *
 * Return: true when the PDU was cleared (this call owns the final path).
 */
static bool datafs_pdu_clear(struct datafs_uring_pdu *pdu,
			     struct datafs_devmem_read *read)
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

/**
 * datafs_read_put() - Drop a devmem read reference, freeing it at zero.
 * @read: read state to reference-drop
 */
static void datafs_read_put(struct datafs_devmem_read *read)
{
	if (refcount_dec_and_test(&read->refs))
		kfree(read);
}

static void datafs_devmem_task_work(struct io_tw_req tw_req,
				    io_tw_token_t tw);

/**
 * datafs_devmem_schedule() - Queue one uring task-work unit if pending.
 * @read: command read state
 *
 * Prevents duplicate task work; extra wakeups are coalesced into a pending bit
 * that is retried after the outstanding unit runs.
 */
static void datafs_devmem_schedule(struct datafs_devmem_read *read)
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
	io_uring_cmd_complete_in_task(read->cmd, datafs_devmem_task_work);
}

/**
 * datafs_socket_wake() - Wake callback translating socket events to task work.
 * @wait: waitqueue entry embedded in the read state
 * @mode: waitqueue wake mode (unused)
 * @sync: whether the wakeup is synchronous (unused)
 * @key: poll wake key (unused)
 *
 * Return: always 0.
 */
static int datafs_socket_wake(wait_queue_entry_t *wait, unsigned int mode,
			      int sync, void *key)
{
	struct datafs_devmem_read *read =
		container_of(wait, struct datafs_devmem_read, socket_wait);

	datafs_devmem_schedule(read);
	return 0;
}

/**
 * datafs_devmem_timeout() - Mark a command timed out and reschedule it.
 * @timer: timer embedded in the read state
 */
static void datafs_devmem_timeout(struct timer_list *timer)
{
	struct datafs_devmem_read *read =
		timer_container_of(read, timer, timer);

	WRITE_ONCE(read->timed_out, true);
	datafs_devmem_schedule(read);
}

/**
 * datafs_remove_loan_waiter() - Unlink a command from the loan-wait list.
 * @read: command read state
 */
static void datafs_remove_loan_waiter(struct datafs_devmem_read *read)
{
	spin_lock(&read->sbi->loan_lock);
	if (read->waiting) {
		list_del_init(&read->wait_link);
		read->waiting = false;
	}
	spin_unlock(&read->sbi->loan_lock);
}

/**
 * datafs_wait_for_socket() - Queue a command for a socket loan, or EAGAIN.
 * @read: command read state
 * @ret: error from the failed loan attempt
 *
 * When the command opted into DATAFS_URING_F_WAIT_SOCKET and the failure is
 * transient (no socket available), the command is added to the FIFO waiter
 * list and -EAGAIN returned for later retry. Otherwise @ret is returned.
 */
static int datafs_wait_for_socket(struct datafs_devmem_read *read, int ret)
{
	if (!(read->flags & DATAFS_URING_F_WAIT_SOCKET) ||
	    read->loan->bpf.sk || (ret != -EAGAIN && ret != -ENOENT))
		return ret;

	datafs_loan_put(read->loan);
	read->loan = NULL;
	spin_lock(&read->sbi->loan_lock);
	if (!read->waiting) {
		list_add_tail(&read->wait_link, &read->sbi->loan_waiters);
		read->waiting = true;
	}
	spin_unlock(&read->sbi->loan_lock);
	/* Close the race with a socket being returned before list insertion. */
	if (!read->socket_retry) {
		read->socket_retry = true;
		atomic_set(&read->pending, 1);
	}
	return -EAGAIN;
}

/**
 * datafs_acquire_loan() - Ask BPF for a socket and create a token-tracking
 * loan.
 * @read: command read state
 *
 * On success the loan stores the provider socket, resolves the matching RX
 * dma-buf, and registers the loan under a mount-visible ID.  It deliberately
 * does not CPU-map the dma-buf because GPU exporters need not support vmap.
 *
 * Return: 0 on success, -EAGAIN with the command queued for a socket, or a
 * negative errno.
 */
static int datafs_acquire_loan(struct datafs_devmem_read *read)
{
	struct datafs_devmem_loan *loan;
	struct socket *socket;
	struct sock *sk;
	u32 id;
	int ret;

	if (read->loan)
		return 0;
	datafs_remove_loan_waiter(read);
	loan = kzalloc_obj(*loan, GFP_KERNEL);
	if (!loan)
		return -ENOMEM;
	refcount_set(&loan->refs, 1); /* Active command ownership. */
	loan->sbi = read->sbi;
	mutex_init(&loan->token_lock);
	xa_init(&loan->tokens);
	atomic_set(&loan->outstanding, 0);
	atomic_set(&loan->releasing, 0);
	read->loan = loan;

	if (!read->sbi->ops->loan_socket || !read->sbi->ops->return_socket)
		return -EOPNOTSUPP;
	loan->bpf.id = read->ctx->id;
	loan->bpf.ino = read->ctx->ino;
	loan->bpf.offset = read->ctx->offset;
	loan->bpf.len = read->ctx->len;
	loan->bpf.path_len = read->ctx->path_len;
	memcpy(loan->bpf.path, read->ctx->path, sizeof(loan->bpf.path));

	ret = datafs_bpf_loan_socket(read->sbi->ops->loan_socket, &loan->bpf);
	if (ret > 0)
		ret = -EPROTO;
	if (ret)
		return datafs_wait_for_socket(read, ret);
	if (loan->bpf.error)
		return datafs_wait_for_socket(read, loan->bpf.error < 0 ?
					      loan->bpf.error : -EPROTO);
	sk = loan->bpf.sk;
	if (!sk || !sk_fullsock(sk) || sk->sk_protocol != IPPROTO_TCP ||
	    sk->sk_type != SOCK_STREAM)
		return -EPROTOTYPE;
	if (sock_net(sk) != read->sbi->net_ns)
		return -EXDEV;
	if (READ_ONCE(sk->sk_state) != TCP_ESTABLISHED)
		return -ENOTCONN;
	socket = READ_ONCE(sk->sk_socket);
	if (!socket || READ_ONCE(socket->sk) != sk)
		return -ENOTSOCK;

	loan->dmabuf = net_devmem_get_rx_dmabuf(read->dmabuf_id, sk);
	if (IS_ERR(loan->dmabuf)) {
		ret = PTR_ERR(loan->dmabuf);
		loan->dmabuf = NULL;
		return ret;
	}
	loan->dmabuf_id = read->dmabuf_id;
	ret = xa_alloc_cyclic(&read->sbi->devmem_loans, &id, loan,
			      XA_LIMIT(0, U16_MAX),
			      &read->sbi->next_loan_id, GFP_KERNEL);
	if (ret)
		return ret;
	loan->id = id;
	loan->registered = true;
	refcount_inc(&loan->refs); /* Active-loan registry ownership. */

	init_waitqueue_func_entry(&read->socket_wait, datafs_socket_wake);
	add_wait_queue(sk_sleep(sk), &read->socket_wait);
	read->socket_waiting = true;
	mod_timer(&read->timer, jiffies +
		  msecs_to_jiffies(read->sbi->opts.timeout_ms));
	return 0;
}

/**
 * datafs_prepare_request() - Build and frame the protocol request.
 * @read: command read state
 *
 * Invokes the provider build_request/frame_tx callbacks and records the framed
 * payload as the pending request.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_prepare_request(struct datafs_devmem_read *read)
{
	struct tcpfs_ctx *ctx = read->ctx;
	const struct tcpfs_ops *ops = read->sbi->ops;
	int ret;

	if (!ops->build_request || !ops->frame_tx || !ops->recv_response ||
	    !ops->unframe_rx ||
	    !ops->handle_response)
		return -EOPNOTSUPP;
	if (ops->conn_style == TCPFS_CONN_OVERLAP)
		return -EOPNOTSUPP;
	ret = datafs_bpf_build_request(ops->build_request, ctx);
	if (ret > 0)
		ret = -EPROTO;
	if (!ret)
		ret = datafs_bpf_frame_tx(ops->frame_tx, ctx);
	if (ret > 0)
		ret = -EPROTO;
	if (ret)
		return ret;
	if (!ctx->payload_len || ctx->payload_len > sizeof(ctx->payload))
		return -EPROTO;
	read->request_len = ctx->payload_len;
	read->request_ready = true;
	return 0;
}

/**
 * datafs_send_request() - Send the framed request without blocking.
 * @read: command read state
 *
 * Sends the request payload, retrying short writes. Returns -EAGAIN when the
 * socket buffer blocks so the command can resume from task context.
 *
 * Return: 0 when fully sent, or a negative errno.
 */
static int datafs_send_request(struct datafs_devmem_read *read)
{
	struct sock *sk = read->loan->bpf.sk;
	struct socket *sock = sk->sk_socket;
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
	struct kvec iov;
	int ret;

	while (read->sent < read->request_len) {
		iov.iov_base = read->ctx->payload + read->sent;
		iov.iov_len = read->request_len - read->sent;
		ret = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK)
			return -EAGAIN;
		if (ret <= 0)
			return ret ?: -EPIPE;
		read->sent += ret;
	}
	return 0;
}

/**
 * datafs_recv_segments() - Receive linear/dma-buf fragments nonblocking.
 * @read: command read state
 * @linear: buffer for linear fragment data
 * @len: bytes requested
 * @segs: decoded fragment descriptors
 * @nr_segs: number of decoded fragments
 * @linear_len: number of bytes delivered into @linear
 *
 * Return: bytes received (may be 0), or a negative errno.
 */
static int datafs_recv_segments(struct datafs_devmem_read *read, void *linear,
				size_t len, struct datafs_devmem_seg *segs,
				unsigned int *nr_segs, size_t *linear_len)
{
	size_t control_len = CMSG_SPACE(sizeof(struct dmabuf_cmsg)) *
		DATAFS_DEVMEM_SEGS;
	void *control;
	struct sock *sk = read->loan->bpf.sk;
	struct socket *sock = sk->sk_socket;
	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
	};
	struct msghdr control_msg;
	struct cmsghdr *cmsg;
	struct kvec iov = { .iov_base = linear, .iov_len = len };
	size_t described = 0;
	int ret;

	control = kmalloc(control_len, GFP_KERNEL);
	if (!control)
		return -ENOMEM;
	msg.msg_control = control;
	msg.msg_controllen = control_len;
	*nr_segs = 0;
	ret = kernel_recvmsg(sock, &msg, &iov, 1, len,
			     MSG_DONTWAIT | MSG_SOCK_DEVMEM);
	if (ret <= 0)
		goto out;
	*linear_len = len - iov_iter_count(&msg.msg_iter);
	control_msg = msg;
	control_msg.msg_control = control;
	control_msg.msg_controllen = control_len - msg.msg_controllen;

	for_each_cmsghdr(cmsg, &control_msg) {
		struct datafs_devmem_seg *seg;

		if (!CMSG_OK(&control_msg, cmsg))
			goto err_proto;
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    (cmsg->cmsg_type != SCM_DEVMEM_LINEAR &&
		     cmsg->cmsg_type != SCM_DEVMEM_DMABUF))
			continue;
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct dmabuf_cmsg)) ||
		    *nr_segs == DATAFS_DEVMEM_SEGS)
			goto err_proto;
		seg = &segs[(*nr_segs)++];
		memcpy(&seg->cmsg, CMSG_DATA(cmsg), sizeof(seg->cmsg));
		seg->dmabuf = cmsg->cmsg_type == SCM_DEVMEM_DMABUF;
		if (!seg->cmsg.frag_size ||
		    seg->cmsg.flags ||
		    (!seg->dmabuf && (seg->cmsg.frag_offset ||
					 seg->cmsg.frag_token ||
					 seg->cmsg.dmabuf_id)) ||
		    check_add_overflow(described,
				       (size_t)seg->cmsg.frag_size, &described))
			goto err_proto;
	}
	if (msg.msg_flags & MSG_CTRUNC)
		goto err_msgsize;
	if (!*nr_segs) {
		if (*linear_len != ret)
			goto err_proto;
		segs[0].cmsg.frag_size = ret;
		segs[0].dmabuf = false;
		*nr_segs = 1;
		described = ret;
	}
	if (described != ret)
		goto err_proto;
out:
	kfree(control);
	return ret;
err_msgsize:
	while (*nr_segs) {
		(*nr_segs)--;
		if (segs[*nr_segs].dmabuf)
			datafs_recycle_token(read->loan,
					     segs[*nr_segs].cmsg.frag_token);
	}
	ret = -EMSGSIZE;
	goto out;
err_proto:
	while (*nr_segs) {
		(*nr_segs)--;
		if (segs[*nr_segs].dmabuf)
			datafs_recycle_token(read->loan,
					     segs[*nr_segs].cmsg.frag_token);
	}
	ret = -EPROTO;
	goto out;
}

/**
 * datafs_post_copy_request() - Ask userspace to stage protocol bytes.
 * @read: command waiting for a device-memory header fragment
 * @cmsg: device-memory range which BPF must inspect
 *
 * Publishes a CQE32 containing an opaque key and dma-buf offset.  Userspace
 * can satisfy it with CUDA or another exporter-specific transfer into a
 * registered host buffer, then submit DATAFS_URING_CMD_COPY_RESPONSE.  The
 * networking token stays with the kernel while that transfer is outstanding.
 *
 * Return: -EAGAIN after publication, or a negative errno.
 */
static int datafs_post_copy_request(struct datafs_devmem_read *read,
				    const struct dmabuf_cmsg *cmsg)
{
	union {
		struct datafs_uring_copy_cqe cqe;
		u64 extra[2];
	} ext = { .cqe.frag_offset = cmsg->frag_offset };
	u32 flags = IORING_CQE_F_MORE | DATAFS_DEVMEM_CQE_F_COPY_REQUEST;
	size_t len = min_t(size_t, cmsg->frag_size,
			   sizeof(read->ctx->rx) - read->ctx->rx_len);
	u32 key;
	int ret;

	if (!len || cmsg->dmabuf_id != read->dmabuf_id ||
	    cmsg->frag_offset > read->loan->dmabuf->size ||
	    cmsg->frag_size > read->loan->dmabuf->size - cmsg->frag_offset)
		return -EPROTO;

	refcount_inc(&read->refs); /* Copy-request registry ownership. */
	ret = xa_alloc_cyclic(&read->sbi->devmem_copies, &key, read,
			      XA_LIMIT(1, U32_MAX),
			      &read->sbi->next_copy_id, GFP_KERNEL);
	if (ret) {
		datafs_read_put(read);
		return ret;
	}
	read->copy_key = key;
	read->copy_len = len;
	read->copy_pending = true;
	ext.cqe.key = key;
	if (!io_uring_cmd_post_cqe32(read->cmd, len, flags,
				     ext.extra[0], ext.extra[1])) {
		xa_erase(&read->sbi->devmem_copies, key);
		read->copy_pending = false;
		datafs_read_put(read);
		return -EOPNOTSUPP;
	}
	return -EAGAIN;
}

/**
 * datafs_recv_header() - Receive framing data for the file-data run.
 * @read: command read state
 *
 * Receives and decodes the protocol response and file-data header, then runs
 * the unframe_rx/handle_response callbacks so BPF identifies the run and the
 * endpoint of the file-data stream.
 *
 * Return: 0 on success, -EAGAIN when more framing is needed, or a negative
 * errno.
 */
static int datafs_recv_header(struct datafs_devmem_read *read)
{
	struct tcpfs_ctx *ctx = read->ctx;
	size_t frame_len;
	int ret;

	if (read->copy_pending)
		return -EAGAIN;
	if (read->header_seg == read->header_nr_segs &&
	    !read->header_parse_pending) {
		if (ctx->rx_len == sizeof(ctx->rx))
			return -EMSGSIZE;
		read->header_seg = 0;
		read->header_nr_segs = 0;
		read->header_linear_len = 0;
		read->header_linear_pos = 0;
		ret = datafs_recv_segments(read, read->header_linear,
					   min_t(size_t, PAGE_SIZE,
						 sizeof(ctx->rx) - ctx->rx_len),
					   read->header_segs,
					   &read->header_nr_segs,
					   &read->header_linear_len);
		if (ret <= 0)
			return ret;
	}
	while (read->header_seg < read->header_nr_segs) {
		struct datafs_devmem_seg *seg =
			&read->header_segs[read->header_seg];

		if (seg->dmabuf && seg->header_copied)
			break;
		if (seg->dmabuf)
			return datafs_post_copy_request(read, &seg->cmsg);
		if (seg->cmsg.frag_size > sizeof(ctx->rx) - ctx->rx_len)
			pr_err("datafs: linear header frag=%u rx=%u linear=%zu\n",
			       seg->cmsg.frag_size, ctx->rx_len,
			       read->header_linear_len);
		if (seg->cmsg.frag_size > sizeof(ctx->rx) - ctx->rx_len)
			return -EMSGSIZE;
		if (read->header_linear_pos > read->header_linear_len ||
		    seg->cmsg.frag_size > read->header_linear_len -
					    read->header_linear_pos)
			return -EPROTO;
		memcpy(ctx->rx + ctx->rx_len,
		       read->header_linear + read->header_linear_pos,
			       seg->cmsg.frag_size);
		read->header_linear_pos += seg->cmsg.frag_size;
		ctx->rx_len += seg->cmsg.frag_size;
		read->header_seg++;
	}
	read->header_parse_pending = false;

	ctx->frame_len = 0;
	memset(&ctx->result, 0, sizeof(ctx->result));
	ret = datafs_bpf_recv_response(read->sbi->ops->recv_response, ctx);
	if (ret > 0)
		ret = -EPROTO;
	if (ret == -EAGAIN) {
		if (read->header_seg < read->header_nr_segs)
			read->header_segs[read->header_seg].header_copied = false;
		return ret;
	}
	if (ret)
		return ret;
	if (ctx->result.id && ctx->result.id != ctx->id) {
		ret = -EPROTO;
		return ret;
	}
	memset(&ctx->result, 0, sizeof(ctx->result));
	ret = datafs_bpf_unframe_rx(read->sbi->ops->unframe_rx, ctx->rx,
				    ctx->rx_len, &frame_len);
	if (ret == -EAGAIN)
		return ret;
	if (ret)
		return ret;
	ctx->frame_len = frame_len;
	ret = datafs_bpf_handle_response(read->sbi->ops->handle_response, ctx);
	if (ret > 0)
		ret = -EPROTO;
	if (ret)
		return ret;
	if (ctx->result.error) {
		ret = ctx->result.error < 0 ? ctx->result.error : -EPROTO;
		return ret;
	}
	if (ctx->result.type == TCPFS_RESULT_CONTINUE) {
		ret = -EOPNOTSUPP;
		return ret;
	}
	if (ctx->result.id && ctx->result.id != ctx->id) {
		ret = -EAGAIN;
		return ret;
	}
	if (ctx->result.type != TCPFS_RESULT_DATA ||
	    !ctx->result.rx_run.data_len ||
	    ctx->result.rx_run.data_len > ctx->len ||
	    ctx->result.rx_run.wire_len > SIZE_MAX ||
	    ctx->result.rx_run.rx_offset > ctx->rx_len ||
	    ctx->result.rx_run.wire_len < ctx->result.rx_run.data_len ||
	    ctx->result.rx_run.flags & ~TCPFS_RX_RUN_F_MASK ||
	    !(ctx->result.rx_run.flags & TCPFS_RX_RUN_F_FRAME_END) ||
	    ctx->rx_len - ctx->result.rx_run.rx_offset >
		ctx->result.rx_run.wire_len) {
		ret = -EPROTO;
		return ret;
	}
	if (ctx->result.offset && ctx->result.offset != ctx->offset) {
		ret = -EPROTO;
		return ret;
	}
	read->target_len = ctx->result.rx_run.data_len;
	read->wire_len = ctx->result.rx_run.wire_len;
	read->wire_done = ctx->rx_len - ctx->result.rx_run.rx_offset;
	if (ctx->result.payload_len !=
	    min_t(size_t, read->wire_done, read->target_len)) {
		ret = -EPROTO;
		return ret;
	}
	read->response_ready = true;
	return 0;
}

/**
 * datafs_post_host() - Copy and publish a linear fallback extent.
 * @read: command read state
 * @data: host buffer bytes to publish
 * @len: byte length
 *
 * Reserves a provided buffer, copies the extent, and posts a CQE32 carrying
 * the buffer bid under the command's host group.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_post_host(struct datafs_devmem_read *read,
			    const void *data, size_t len)
{
	union {
		struct datafs_uring_devmem_cqe cqe;
		u64 extra[2];
	} ext = {};
	struct io_uring_cmd_pbuf pbuf;
	void *addr;
	u32 flags;
	int ret;

	if (!len)
		return 0;
	if (len > PAGE_SIZE)
		return -E2BIG;
	if (!read->pbuf_owned) {
		ret = io_uring_cmd_pbuf_acquire(read->cmd, read->host_group,
						IO_URING_CMD_TASK_WORK_ISSUE_FLAGS);
		if (ret)
			return ret;
		read->pbuf_owned = true;
	}
	ret = io_uring_cmd_pbuf_reserve(read->cmd, read->host_group,
					&pbuf,
					IO_URING_CMD_TASK_WORK_ISSUE_FLAGS);
	if (ret) {
		pr_debug("datafs: host reserve failed id=%llu copied=%zu ret=%d\n",
			 read->ctx->id, read->copied, ret);
		return ret;
	}
	addr = kmap_local_page(pbuf.page);
	memcpy(addr, data, len);
	kunmap_local(addr);
	flags = IORING_CQE_F_MORE | IORING_CQE_F_BUFFER |
		((u32)pbuf.bid << IORING_CQE_BUFFER_SHIFT);
	if (!io_uring_cmd_post_cqe32(read->cmd, len, flags,
				     ext.extra[0], ext.extra[1])) {
		io_uring_cmd_pbuf_put(read->cmd, &pbuf);
		return -EOPNOTSUPP;
	}
	io_uring_cmd_pbuf_put(read->cmd, &pbuf);
	return 0;
}

/**
 * datafs_post_dmabuf() - Publish a dma-buf extent, transferring its token.
 * @read: command read state
 * @cmsg: dma-buf fragment descriptor
 * @len: file extent length from the fragment
 *
 * Records the fragment's token as outstanding and posts a CQE32 carrying the
 * dma-buf fractional offset and token to userspace.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_post_dmabuf(struct datafs_devmem_read *read,
			      const struct dmabuf_cmsg *cmsg, size_t len)
{
	union {
		struct datafs_uring_devmem_cqe cqe;
		u64 extra[2];
	} ext = {
		.cqe.frag_offset = cmsg->frag_offset,
		.cqe.frag_token = cmsg->frag_token,
		.cqe.dmabuf_id = cmsg->dmabuf_id,
	};
	u32 flags = IORING_CQE_F_MORE |
		((u32)read->loan->id << DATAFS_DEVMEM_CQE_LOAN_SHIFT);
	int ret;

	if (cmsg->dmabuf_id != read->dmabuf_id ||
	    cmsg->frag_offset > read->loan->dmabuf->size ||
	    cmsg->frag_size > read->loan->dmabuf->size - cmsg->frag_offset)
		return -EPROTO;
	ret = datafs_record_token(read->loan, cmsg->frag_token);
	if (ret) {
		pr_debug("datafs: token record failed id=%llu token=%u ret=%d\n",
			 read->ctx->id, cmsg->frag_token, ret);
		return ret;
	}
	if (!io_uring_cmd_post_cqe32(read->cmd, len, flags,
				     ext.extra[0], ext.extra[1])) {
		datafs_forget_tokens(read->loan, cmsg->frag_token, 1);
		return -EOPNOTSUPP;
	}
	return 0;
}

/**
 * datafs_post_initial() - Publish file bytes received with the header.
 * @read: command read state
 *
 * Chunks and publishes the file data already present alongside the parsed
 * protocol header.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_post_initial(struct datafs_devmem_read *read)
{
	struct tcpfs_ctx *ctx = read->ctx;
	size_t available;
	int ret;

	available = ctx->result.payload_len;
	while (available) {
		size_t len = min_t(size_t, available, PAGE_SIZE);

		ret = datafs_post_host(read,
				       ctx->rx + ctx->result.rx_run.rx_offset +
				       read->copied, len);
		if (ret)
			return ret;
		read->copied += len;
		available -= len;
	}
	return 0;
}

/**
 * datafs_recv_body() - Receive and publish the file-data body.
 * @read: command read state
 *
 * Receives the remaining provider-declared file extent and publishes each
 * fragment (dma-buf or linear host fallback) until the wire length is met.
 *
 * Return: copied count when complete, -EAGAIN while awaiting more data, or a
 * negative errno.
 */
static int datafs_recv_body(struct datafs_devmem_read *read)
{
	struct datafs_devmem_seg segs[DATAFS_DEVMEM_SEGS];
	u8 *linear;
	size_t linear_len, linear_pos = 0;
	unsigned int nr_segs, i;
	int ret;

	while (read->header_seg < read->header_nr_segs) {
		struct datafs_devmem_seg *seg =
			&read->header_segs[read->header_seg];
		size_t data_len = 0;

		if (!seg->dmabuf || !seg->header_copied)
			return -EPROTO;
		if (read->copied < read->target_len)
			data_len = min_t(size_t, seg->cmsg.frag_size,
					 read->target_len - read->copied);
		if (data_len)
			ret = datafs_post_dmabuf(read, &seg->cmsg, data_len);
		else
			ret = datafs_recycle_token(read->loan,
						   seg->cmsg.frag_token) == 1 ?
				0 : -EPROTO;
		if (ret)
			return ret;
		read->copied += data_len;
		read->wire_done += seg->cmsg.frag_size;
		read->header_seg++;
	}
	if (read->wire_done >= read->wire_len)
		return read->copied;
	linear = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!linear)
		return -ENOMEM;
	ret = datafs_recv_segments(read, linear,
				   min_t(size_t, PAGE_SIZE,
					 read->wire_len - read->wire_done),
				   segs, &nr_segs, &linear_len);
	if (ret <= 0) {
		if (ret != -EAGAIN && ret != -EWOULDBLOCK)
			pr_debug("datafs: body receive failed id=%llu copied=%zu ret=%d\n",
				 read->ctx->id, read->copied, ret);
		goto out;
	}
	for (i = 0; i < nr_segs; i++) {
		struct datafs_devmem_seg *seg = &segs[i];
		size_t data_len = 0;

		if (read->copied < read->target_len)
			data_len = min_t(size_t, seg->cmsg.frag_size,
					 read->target_len - read->copied);
		if (seg->dmabuf) {
			if (data_len)
				ret = datafs_post_dmabuf(read, &seg->cmsg,
							 data_len);
			else
				ret = datafs_recycle_token(read->loan,
							   seg->cmsg.frag_token) == 1 ?
					0 : -EPROTO;
		} else {
			if (linear_pos > linear_len ||
			    seg->cmsg.frag_size > linear_len - linear_pos) {
				ret = -EPROTO;
				goto out_return;
			}
			ret = datafs_post_host(read, linear + linear_pos,
					       data_len);
			linear_pos += seg->cmsg.frag_size;
		}
		if (ret) {
			if (seg->dmabuf)
				datafs_recycle_token(read->loan,
						     seg->cmsg.frag_token);
			goto out_return;
		}
		read->copied += data_len;
		read->wire_done += seg->cmsg.frag_size;
	}
	ret = read->wire_done >= read->wire_len ? read->copied : -EAGAIN;
	goto out;

out_return:
	for (i++; i < nr_segs; i++)
		if (segs[i].dmabuf)
			datafs_recycle_token(read->loan,
					     segs[i].cmsg.frag_token);
out:
	kfree(linear);
	return ret;
}

/**
 * datafs_devmem_drive() - Advance a devmem command until it must retry.
 * @read: command read state
 *
 * Runs acquire/prepare/send/receive/publish in order, returning -EAGAIN when
 * more socket data or a socket loan is needed so the caller can resume from
 * task context.
 *
 * Return: 0 on success, -EAGAIN/-ETIMEDOUT/-ECANCELED for retry, or a negative
 * errno.
 */
static int datafs_devmem_drive(struct datafs_devmem_read *read)
{
	int ret;

	if (READ_ONCE(read->copy_pending))
		return -EAGAIN;
	if (read->copy_error)
		return read->copy_error;
	if (READ_ONCE(read->cancelled))
		return -ECANCELED;
	if (READ_ONCE(read->timed_out))
		return -ETIMEDOUT;
	ret = datafs_acquire_loan(read);
	if (ret)
		return ret;
	if (!read->request_ready) {
		ret = datafs_prepare_request(read);
		if (ret)
			return ret;
	}
	if (read->sent < read->request_len) {
		ret = datafs_send_request(read);
		if (ret)
			return ret;
	}
	if (!read->response_ready) {
		ret = datafs_recv_header(read);
		if (ret)
			return ret;
		ret = datafs_post_initial(read);
		if (ret)
			return ret;
		read->initial_posted = true;
	}
	if (!read->initial_posted)
		return -EPROTO;
	return datafs_recv_body(read);
}

/**
 * datafs_read_cleanup() - Disarm callbacks and release command state.
 * @read: command read state
 * @issue_flags: issue flags for pbuf release
 *
 * Removes socket and timeout wakeups, unmaps the dma-buf, releases the host
 * buffer group, returns the loaned socket, and frees command allocations.
 */
static void datafs_read_cleanup(struct datafs_devmem_read *read,
				unsigned int issue_flags)
{
	unsigned int i;

	datafs_remove_loan_waiter(read);
	if (read->socket_waiting) {
		remove_wait_queue(sk_sleep(read->loan->bpf.sk),
				  &read->socket_wait);
		read->socket_waiting = false;
	}
	timer_shutdown_sync(&read->timer);
	if (read->loan) {
		for (i = read->header_seg; i < read->header_nr_segs; i++) {
			u32 token = read->header_segs[i].cmsg.frag_token;

			if (read->header_segs[i].dmabuf)
				datafs_recycle_token(read->loan, token);
		}
	}
	if (read->pbuf_owned)
		io_uring_cmd_pbuf_release(read->cmd, read->host_group,
					  issue_flags);
	if (read->loan) {
		WRITE_ONCE(read->loan->command_done, true);
		datafs_release_loan_if_idle(read->loan);
		datafs_loan_put(read->loan);
		read->loan = NULL;
	}
	kfree(read->ctx);
	read->ctx = NULL;
	kfree(read->header_linear);
	read->header_linear = NULL;
}

/**
 * datafs_devmem_task_work() - Resume one devmem command from task context.
 * @tw_req: task-work request wrapping the command
 * @tw: task-work token (cancelled flag)
 *
 * Drives the command, re-arming the socket wakeup when it needs more data, and
 * posts the terminal CQE through cleanup once it completes or fails.
 */
static void datafs_devmem_task_work(struct io_tw_req tw_req,
				    io_tw_token_t tw)
{
	struct io_uring_cmd *cmd = io_uring_cmd_from_tw(tw_req);
	struct datafs_uring_pdu *pdu =
		io_uring_cmd_to_pdu(cmd, struct datafs_uring_pdu);
	struct datafs_devmem_read *read = datafs_pdu_get(pdu);
	int ret;

	if (!read)
		return;
	if (tw.cancel)
		WRITE_ONCE(read->cancelled, true);
	ret = datafs_devmem_drive(read);
	if (ret == -EAGAIN && !READ_ONCE(read->cancelled) &&
	    !READ_ONCE(read->timed_out)) {
		if (!READ_ONCE(read->copy_pending) && read->loan &&
		    read->loan->bpf.sk) {
			struct sock *sk = read->loan->bpf.sk;
			struct sk_buff_head *queue = &sk->sk_receive_queue;

			if (!skb_queue_empty_lockless(queue))
				atomic_set(&read->pending, 1);
		}
		atomic_set(&read->scheduled, 0);
		if (atomic_xchg(&read->pending, 0))
			datafs_devmem_schedule(read);
		datafs_read_put(read);
		return;
	}

	WRITE_ONCE(read->done, true);
	read->final_ret = ret;
	io_uring_cmd_commit_cqes(cmd);
	if (!datafs_pdu_clear(pdu, read)) {
		datafs_read_put(read);
		return;
	}
	datafs_read_cleanup(read, IO_URING_CMD_TASK_WORK_ISSUE_FLAGS);
	io_uring_cmd_done(cmd, ret, IO_URING_CMD_TASK_WORK_ISSUE_FLAGS);
	datafs_read_put(read); /* PDU owner. */
	datafs_read_put(read); /* This task-work invocation. */
}

/**
 * datafs_devmem_read() - Start a TCP-devmem receive command for a regular file.
 * @sbi: superblock
 * @path: root-relative object path
 * @path_len: length of @path
 * @ino: remote inode number
 * @offset: byte offset
 * @len: byte length to read
 * @host_group: PAGE_SIZE provided-buffer group for host fallback
 * @dmabuf_id: netdev RX dma-buf binding ID
 * @flags: DATAFS_URING_F_* command flags
 * @cmd: uring command
 * @issue_flags: command issue flags
 *
 * Allocates command state, marks the command cancelable, and schedules the
 * first task-work unit.
 *
 * Return: -EIOCBQUEUED, or a negative errno.
 */
int datafs_devmem_read(struct datafs_sb_info *sbi, const char *path,
		       u32 path_len, u64 ino, u64 offset, size_t len,
		       u16 host_group, u32 dmabuf_id, u32 flags,
		       struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct datafs_uring_pdu *pdu =
		io_uring_cmd_to_pdu(cmd, struct datafs_uring_pdu);
	struct datafs_devmem_read *read;
	struct tcpfs_ctx *ctx;

	if (!(issue_flags & IO_URING_F_CQE32))
		return -EOPNOTSUPP;
	if (!sbi->ops->loan_socket || !sbi->ops->return_socket)
		return -EOPNOTSUPP;
	read = kzalloc_obj(*read, GFP_NOWAIT);
	ctx = kzalloc_obj(*ctx, GFP_NOWAIT);
	if (read)
		read->header_linear = kmalloc(PAGE_SIZE, GFP_NOWAIT);
	if (!read || !ctx || !read->header_linear) {
		if (read)
			kfree(read->header_linear);
		kfree(read);
		kfree(ctx);
		return -ENOMEM;
	}
	spin_lock_init(&pdu->lock);
	pdu->read = read;
	refcount_set(&read->refs, 1);
	mutex_init(&read->copy_lock);
	INIT_LIST_HEAD(&read->wait_link);
	timer_setup(&read->timer, datafs_devmem_timeout, 0);
	read->cmd = cmd;
	read->sbi = sbi;
	read->ctx = ctx;
	read->host_group = host_group;
	read->dmabuf_id = dmabuf_id;
	read->flags = flags;
	atomic_set(&read->scheduled, 0);
	atomic_set(&read->pending, 0);

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

	io_uring_cmd_mark_cancelable(cmd, issue_flags);
	WRITE_ONCE(read->armed, true);
	datafs_devmem_schedule(read);
	return -EIOCBQUEUED;
}

/**
 * datafs_devmem_cancel() - Cancel an active devmem command.
 * @cmd: uring command to cancel
 *
 * Marks the command cancelled and schedules task work so cleanup drops the
 * loan and posts the terminal CQE.
 *
 * Return: 0.
 */
int datafs_devmem_cancel(struct io_uring_cmd *cmd)
{
	struct datafs_uring_pdu *pdu =
		io_uring_cmd_to_pdu(cmd, struct datafs_uring_pdu);
	struct datafs_devmem_read *read = datafs_pdu_get(pdu);

	if (!read)
		return 0;
	WRITE_ONCE(read->cancelled, true);
	datafs_devmem_schedule(read);
	datafs_read_put(read);
	return 0;
}

/**
 * datafs_devmem_copy_response() - Consume userspace-staged protocol bytes.
 * @sbi: superblock owning the original receive command
 * @cmd: COPY_RESPONSE command selecting a registered host buffer
 * @issue_flags: io_uring issue context used to import that fixed buffer
 *
 * Matches the opaque key from a COPY_REQUEST CQE, copies exactly the requested
 * bytes into the original BPF receive context, returns the held networking
 * token, and wakes the original command.  A failed buffer import leaves the
 * request pending so userspace may retry it.
 *
 * Return: copied byte count, or a negative errno.
 */
int datafs_devmem_copy_response(struct datafs_sb_info *sbi,
				struct io_uring_cmd *cmd,
				unsigned int issue_flags)
{
	const struct io_uring_sqe *sqe = cmd->sqe;
	const struct datafs_uring_copy_cmd *ccmd =
		io_uring_sqe_cmd(sqe, struct datafs_uring_copy_cmd);
	struct datafs_devmem_read *read;
	struct datafs_devmem_seg *seg;
	struct iov_iter iter;
	u64 key = READ_ONCE(ccmd->key);
	size_t len = READ_ONCE(sqe->len);
	int ret;

	if (!key || key > U32_MAX || !len || ccmd->reserved ||
	    !(cmd->flags & IORING_URING_CMD_FIXED))
		return -EINVAL;
	xa_lock(&sbi->devmem_copies);
	read = xa_load(&sbi->devmem_copies, key);
	if (read && !refcount_inc_not_zero(&read->refs))
		read = NULL;
	xa_unlock(&sbi->devmem_copies);
	if (!read)
		return -ENOENT;

	mutex_lock(&read->copy_lock);
	if (!read->copy_pending || read->copy_key != key ||
	    read->header_seg >= read->header_nr_segs) {
		ret = -ENOENT;
		goto out_unlock;
	}
	seg = &read->header_segs[read->header_seg];
	if (!seg->dmabuf || len != read->copy_len ||
	    len > sizeof(read->ctx->rx) - read->ctx->rx_len) {
		ret = -EINVAL;
		goto out_unlock;
	}
	ret = io_uring_cmd_import_fixed(READ_ONCE(sqe->addr), len, WRITE,
					&iter, cmd, issue_flags);
	if (ret)
		goto out_unlock;
	if (copy_from_iter(read->ctx->rx + read->ctx->rx_len, len, &iter) !=
	    len) {
		ret = -EFAULT;
		goto out_unlock;
	}
	if (xa_erase(&sbi->devmem_copies, key) != read) {
		ret = -ENOENT;
		goto out_unlock;
	}
	read->ctx->rx_len += len;
	read->header_parse_pending = true;
	seg->cmsg.frag_offset += len;
	seg->cmsg.frag_size -= len;
	if (seg->cmsg.frag_size)
		seg->header_copied = true;
	else
		read->header_seg++;
	read->copy_pending = false;
	read->copy_key = 0;
	read->copy_len = 0;
	if (!seg->cmsg.frag_size) {
		ret = datafs_recycle_token(read->loan, seg->cmsg.frag_token);
		if (ret != 1)
			read->copy_error = ret < 0 ? ret : -EPROTO;
	}
	ret = read->copy_error ?: len;
	datafs_devmem_schedule(read);
	datafs_read_put(read); /* Copy-request registry ownership. */
out_unlock:
	mutex_unlock(&read->copy_lock);
	datafs_read_put(read); /* Lookup ownership. */
	return ret;
}

/**
 * datafs_devmem_dontneed() - Return published dma-buf tokens to the kernel.
 * @sbi: superblock
 * @loan_id: mount-visible loan ID owning the tokens
 * @dmabuf_id: dma-buf binding the tokens belong to
 * @token_start: first token
 * @token_count: number of consecutive tokens
 *
 * Looks up the loan, verifies the token range is outstanding, and returns it
 * to the networking allocator.
 *
 * Return: the number of tokens returned, or a negative errno.
 */
int datafs_devmem_dontneed(struct datafs_sb_info *sbi, u16 loan_id,
			   u32 dmabuf_id, u32 token_start,
			   u32 token_count)
{
	struct datafs_devmem_loan *loan;
	int ret;

	if (!token_count || token_count > 1024 ||
	    token_start > U32_MAX - token_count + 1)
		return -EINVAL;
	xa_lock(&sbi->devmem_loans);
	loan = xa_load(&sbi->devmem_loans, loan_id);
	if (loan && !refcount_inc_not_zero(&loan->refs))
		loan = NULL;
	xa_unlock(&sbi->devmem_loans);
	if (!loan)
		return -ENOENT;
	if (dmabuf_id != loan->dmabuf_id)
		ret = -EXDEV;
	else
		ret = datafs_return_token(loan, token_start, token_count);
	datafs_release_loan_if_idle(loan);
	datafs_loan_put(loan);
	return ret;
}

/**
 * datafs_devmem_shutdown() - Stop devmem work before unmount frees state.
 * @sbi: superblock being torn down
 *
 * Returns every outstanding token, marks each loan command-done, and releases
 * every registered loan so no devmem work survives the superblock.
 */
void datafs_devmem_shutdown(struct datafs_sb_info *sbi)
{
	for (;;) {
		struct datafs_devmem_loan *loan;
		unsigned long index = 0;
		unsigned long token;

		xa_lock(&sbi->devmem_loans);
		loan = xa_find(&sbi->devmem_loans, &index, U16_MAX,
			       XA_PRESENT);
		if (loan && !refcount_inc_not_zero(&loan->refs))
			loan = NULL;
		xa_unlock(&sbi->devmem_loans);
		if (!loan)
			break;
		for (;;) {
			void *entry;

			token = 0;
			mutex_lock(&loan->token_lock);
			entry = xa_find(&loan->tokens, &token, U32_MAX,
					XA_PRESENT);
			mutex_unlock(&loan->token_lock);
			if (!entry)
				break;
			if (datafs_return_token(loan, token, 1) != 1)
				datafs_forget_tokens(loan, token, 1);
		}
		WRITE_ONCE(loan->command_done, true);
		datafs_release_loan(loan);
		datafs_loan_put(loan);
	}
}

MODULE_IMPORT_NS("DMA_BUF");
