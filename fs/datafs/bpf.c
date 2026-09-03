// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "datafs.h"

static DEFINE_MUTEX(tcpfs_bpf_lock);
static atomic_t tcpfs_bpf_seq = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(tcpfs_bpf_wait);
static LIST_HEAD(tcpfs_bpf_ops_list);
static const struct btf_type *tcpfs_ctx_type;
static const struct btf_type *tcpfs_build_request_type;
static const struct btf_type *tcpfs_frame_tx_type;
static const struct btf_type *tcpfs_recv_response_type;
static const struct btf_type *tcpfs_unframe_rx_type;
static const struct btf_type *tcpfs_handle_response_type;
static const struct btf_type *tcpfs_loan_socket_type;
static const struct btf_type *tcpfs_return_socket_type;
static const struct btf_type *tcpfs_socket_loan_type;

BTF_ID_LIST_SINGLE(tcpfs_ctx_ids, struct, tcpfs_ctx)
BTF_ID_LIST_SINGLE(tcpfs_build_request_ids, struct, tcpfs_build_request_ctx)
BTF_ID_LIST_SINGLE(tcpfs_frame_tx_ids, struct, tcpfs_frame_tx_ctx)
BTF_ID_LIST_SINGLE(tcpfs_recv_response_ids, struct, tcpfs_recv_response_ctx)
BTF_ID_LIST_SINGLE(tcpfs_unframe_rx_ids, struct, tcpfs_unframe_rx_ctx)
BTF_ID_LIST_SINGLE(tcpfs_handle_response_ids, struct, tcpfs_handle_response_ctx)
BTF_ID_LIST_SINGLE(tcpfs_loan_socket_ids, struct, tcpfs_loan_socket_ctx)
BTF_ID_LIST_SINGLE(tcpfs_return_socket_ids, struct, tcpfs_return_socket_ctx)
BTF_ID_LIST_SINGLE(tcpfs_socket_loan_ids, struct, tcpfs_socket_loan)

__bpf_kfunc_start_defs();

/** Append verifier-bounded bytes to the provider's transmit payload. */
__bpf_kfunc int bpf_tcpfs_payload_append(struct tcpfs_ctx *ctx,
					 const void *src, u32 src__sz)
{
	u32 pos;

	if (!ctx || !src)
		return -EINVAL;
	pos = ctx->payload_len;
	if (src__sz > TCPFS_PAYLOAD_MAX || pos > TCPFS_PAYLOAD_MAX ||
	    src__sz > TCPFS_PAYLOAD_MAX - pos)
		return -ENOSPC;

	memcpy(ctx->payload + pos, src, src__sz);
	ctx->payload_len = pos + src__sz;
	return 0;
}

/** Overwrite an existing payload extent without changing its length. */
__bpf_kfunc int bpf_tcpfs_payload_write(struct tcpfs_ctx *ctx, u32 offset,
					const void *src, u32 src__sz)
{
	if (!ctx || !src)
		return -EINVAL;
	if (offset > ctx->payload_len || src__sz > ctx->payload_len - offset)
		return -ENOSPC;

	memcpy(ctx->payload + offset, src, src__sz);
	return 0;
}

/** Append a verifier-known NUL-terminated string to the payload. */
__bpf_kfunc int bpf_tcpfs_payload_append_str(struct tcpfs_ctx *ctx,
					     const char *src__str)
{
	if (!src__str)
		return -EINVAL;

	return bpf_tcpfs_payload_append(ctx, src__str, strlen(src__str));
}

/** Append the opaque mount argument to a provider request. */
__bpf_kfunc int bpf_tcpfs_payload_append_mount_arg(struct tcpfs_ctx *ctx)
{
	u32 len;

	if (!ctx)
		return -EINVAL;
	len = min_t(u32, ctx->mount_arg_len, sizeof(ctx->mount_arg));
	return bpf_tcpfs_payload_append(ctx, ctx->mount_arg, len);
}

/** Append the current root-relative path to a provider request. */
__bpf_kfunc int bpf_tcpfs_payload_append_path(struct tcpfs_ctx *ctx)
{
	u32 len;

	if (!ctx)
		return -EINVAL;
	len = min_t(u32, ctx->path_len, sizeof(ctx->path));
	return bpf_tcpfs_payload_append(ctx, ctx->path, len);
}

/** Append an unsigned integer in decimal wire format. */
__bpf_kfunc int bpf_tcpfs_payload_append_u64(struct tcpfs_ctx *ctx, u64 value)
{
	char tmp[20];
	u32 len = 0;
	int i;

	if (!ctx)
		return -EINVAL;
	if (!value) {
		tmp[len++] = '0';
	} else {
		while (value && len < sizeof(tmp)) {
			tmp[len++] = '0' + value % 10;
			value /= 10;
		}
	}

	for (i = 0; i < len / 2; i++) {
		char c = tmp[i];

		tmp[i] = tmp[len - i - 1];
		tmp[len - i - 1] = c;
	}

	return bpf_tcpfs_payload_append(ctx, tmp, len);
}

/** Read one byte from a callback context through a verifier-safe kfunc. */
__bpf_kfunc int bpf_tcpfs_ctx_read_byte(struct tcpfs_ctx *ctx, u32 offset)
{
	if (!ctx || offset >= sizeof(*ctx))
		return -EINVAL;

	return *((u8 *)ctx + offset);
}

/** Decode one unaligned big-endian word from a callback context. */
__bpf_kfunc s64 bpf_tcpfs_ctx_read_be32(struct tcpfs_ctx *ctx, u32 offset)
{
	const u8 *p;

	if (!ctx || offset > sizeof(*ctx) - sizeof(u32))
		return -EINVAL;
	p = (u8 *)ctx + offset;

	return (u32)p[0] << 24 | (u32)p[1] << 16 |
	       (u32)p[2] << 8 | p[3];
}

/** Read one byte from the immutable receive window used by unframe_rx. */
__bpf_kfunc int bpf_tcpfs_unframe_rx_read_byte(
	const struct tcpfs_unframe_rx_ctx *ctx, u32 offset)
{
	if (!ctx || !ctx->data || offset >= ctx->len)
		return -EINVAL;

	return ctx->data[offset];
}

/** Find a bounded byte sequence in the immutable unframe receive window. */
__bpf_kfunc int bpf_tcpfs_unframe_rx_find(
	const struct tcpfs_unframe_rx_ctx *ctx, const void *needle,
	u32 needle__sz)
{
	const u8 *p = needle;
	u32 i;

	if (!ctx || !ctx->data || !needle || !needle__sz ||
	    needle__sz > ctx->len)
		return -EINVAL;

	for (i = 0; i <= ctx->len - needle__sz; i++) {
		if (!memcmp(ctx->data + i, p, needle__sz))
			return i;
	}

	return -ENOENT;
}

/** Find a verifier-known string in the immutable unframe receive window. */
__bpf_kfunc int
bpf_tcpfs_unframe_rx_find_str(const struct tcpfs_unframe_rx_ctx *ctx,
			      const char *needle__str)
{
	if (!needle__str)
		return -EINVAL;

	return bpf_tcpfs_unframe_rx_find(ctx, needle__str,
					strlen(needle__str));
}

/** Append metadata or directory bytes to the provider result payload. */
__bpf_kfunc int bpf_tcpfs_result_append(struct tcpfs_ctx *ctx,
					const void *src, u32 src__sz)
{
	u32 pos;

	if (!ctx || !src)
		return -EINVAL;
	pos = ctx->result.payload_len;
	if (src__sz > TCPFS_PAYLOAD_MAX || pos > TCPFS_PAYLOAD_MAX ||
	    src__sz > TCPFS_PAYLOAD_MAX - pos)
		return -ENOSPC;

	memcpy(ctx->result.payload + pos, src, src__sz);
	ctx->result.payload_len = pos + src__sz;
	return 0;
}

/** Copy a bounded receive-window extent into the provider result. */
__bpf_kfunc int bpf_tcpfs_result_append_rx(struct tcpfs_ctx *ctx, u32 offset,
					   u32 len)
{
	if (!ctx)
		return -EINVAL;
	if (offset > ctx->rx_len || offset >= sizeof(ctx->rx))
		return -EINVAL;
	len = min_t(u32, len, ctx->rx_len - offset);
	len = min_t(u32, len, sizeof(ctx->rx) - offset);

	return bpf_tcpfs_result_append(ctx, ctx->rx + offset, len);
}

/** Find a verifier-bounded byte sequence in the receive window. */
__bpf_kfunc int bpf_tcpfs_rx_find_from(struct tcpfs_ctx *ctx, u32 offset,
				       const void *needle, u32 needle__sz)
{
	const u8 *p = needle;
	u32 i, limit;

	if (!ctx || !needle || !needle__sz)
		return -EINVAL;
	limit = min_t(u32, ctx->rx_len, sizeof(ctx->rx));
	if (offset > limit || needle__sz > limit - offset)
		return -ENOENT;

	for (i = offset; i <= limit - needle__sz; i++) {
		if (!memcmp(ctx->rx + i, p, needle__sz))
			return i;
	}

	return -ENOENT;
}

/** Find a byte sequence from the start of the receive window. */
__bpf_kfunc int bpf_tcpfs_rx_find(struct tcpfs_ctx *ctx, const void *needle,
				  u32 needle__sz)
{
	return bpf_tcpfs_rx_find_from(ctx, 0, needle, needle__sz);
}

/** Find a verifier-known string after a specified receive offset. */
__bpf_kfunc int bpf_tcpfs_rx_find_str_from(struct tcpfs_ctx *ctx, u32 offset,
					   const char *needle__str)
{
	if (!needle__str)
		return -EINVAL;

	return bpf_tcpfs_rx_find_from(ctx, offset, needle__str,
				      strlen(needle__str));
}

/** Find a verifier-known string in the receive window. */
__bpf_kfunc int bpf_tcpfs_rx_find_str(struct tcpfs_ctx *ctx,
				      const char *needle__str)
{
	if (!needle__str)
		return -EINVAL;

	return bpf_tcpfs_rx_find(ctx, needle__str, strlen(needle__str));
}

/** Parse an unsigned decimal integer from the receive window. */
__bpf_kfunc int bpf_tcpfs_rx_parse_u64(struct tcpfs_ctx *ctx, u32 offset,
				       u64 *value)
{
	u64 val = 0;
	bool seen = false;

	if (!ctx || !value)
		return -EINVAL;
	if (offset >= ctx->rx_len || offset >= sizeof(ctx->rx))
		return -ENOENT;

	while (offset < ctx->rx_len && offset < sizeof(ctx->rx)) {
		u8 c = ctx->rx[offset++];

		if (!seen && (c == ' ' || c == '\t'))
			continue;
		if (c < '0' || c > '9')
			break;
		if (val > (U64_MAX - (c - '0')) / 10)
			return -EOVERFLOW;
		val = val * 10 + c - '0';
		seen = true;
	}

	if (!seen)
		return -ENOENT;
	*value = val;
	return 0;
}

/**
 * bpf_tcpfs_socket_assign() - Atomically take a socket from a provider SOCKMAP.
 * @loan: loan receiving the borrowed socket
 * @sockmap__map: provider SOCKMAP
 * @key: slot holding the established socket
 *
 * On success the loan owns the socket (removed from the map). On failure the
 * socket is restored to @key and loan->error is set.
 */
__bpf_kfunc void bpf_tcpfs_socket_assign(struct tcpfs_socket_loan *loan,
					 struct bpf_map *sockmap__map, u32 key)
{
	struct sock *sk = NULL;
	int error = 0;

	if (!loan) {
		error = -EINVAL;
	} else if (!sockmap__map) {
		error = -EINVAL;
	} else if (READ_ONCE(loan->sk)) {
		error = -EBUSY;
	} else {
		sk = sock_map_delete_elem_get_sock(sockmap__map, key);
		if (IS_ERR(sk)) {
			error = PTR_ERR(sk);
			sk = NULL;
		} else if (!sk_fullsock(sk) || sk->sk_type != SOCK_STREAM ||
			   sk->sk_protocol != IPPROTO_TCP) {
			error = -EPROTOTYPE;
		} else if (READ_ONCE(sk->sk_state) != TCP_ESTABLISHED) {
			error = -ENOTCONN;
		} else if (cmpxchg(&loan->sk, NULL, sk)) {
			error = -EBUSY;
		}
	}

	if (error) {
		if (loan)
			loan->error = error;
		if (sk) {
			sock_map_update_elem_sock(sockmap__map, key, sk,
						  BPF_NOEXIST);
			sock_put(sk);
		}
	}
}

/**
 * bpf_tcpfs_socket_return() - Put a loaned socket back into a provider SOCKMAP.
 * @loan: loan whose socket is returned
 * @sockmap__map: provider SOCKMAP to restore into
 *
 * Reinserts the socket at the loan's original slot. Mark socket_returned on
 * success.
 *
 * Return: 0 on success, or a negative errno.
 */
__bpf_kfunc int bpf_tcpfs_socket_return(struct tcpfs_socket_loan *loan,
					struct bpf_map *sockmap__map)
{
	u32 key;
	int ret;

	if (!loan || !loan->sk || !sockmap__map)
		return -EINVAL;
	key = loan->socket_key;
	ret = sock_map_update_elem_sock(sockmap__map, key, loan->sk,
					BPF_NOEXIST);
	if (!ret)
		loan->socket_returned = 1;
	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(tcpfs_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_tcpfs_payload_append)
BTF_ID_FLAGS(func, bpf_tcpfs_payload_write)
BTF_ID_FLAGS(func, bpf_tcpfs_payload_append_str)
BTF_ID_FLAGS(func, bpf_tcpfs_payload_append_mount_arg)
BTF_ID_FLAGS(func, bpf_tcpfs_payload_append_path)
BTF_ID_FLAGS(func, bpf_tcpfs_payload_append_u64)
BTF_ID_FLAGS(func, bpf_tcpfs_ctx_read_byte)
BTF_ID_FLAGS(func, bpf_tcpfs_ctx_read_be32)
BTF_ID_FLAGS(func, bpf_tcpfs_unframe_rx_read_byte)
BTF_ID_FLAGS(func, bpf_tcpfs_unframe_rx_find)
BTF_ID_FLAGS(func, bpf_tcpfs_unframe_rx_find_str)
BTF_ID_FLAGS(func, bpf_tcpfs_result_append)
BTF_ID_FLAGS(func, bpf_tcpfs_result_append_rx)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_find_from)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_find)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_find_str_from)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_find_str)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_parse_u64)
BTF_ID_FLAGS(func, bpf_tcpfs_socket_assign)
BTF_ID_FLAGS(func, bpf_tcpfs_socket_return)
BTF_KFUNCS_END(tcpfs_kfunc_set_ids)

static const struct btf_kfunc_id_set tcpfs_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &tcpfs_kfunc_set_ids,
};

/**
 * tcpfs_bpf_get() - Acquire a live struct_ops provider by name.
 * @name: mount-visible provider name
 *
 * Return: a referenced provider entry, or NULL when not attached.
 */
struct tcpfs_bpf_ops *tcpfs_bpf_get(const char *name)
{
	struct tcpfs_bpf_ops *entry;

	mutex_lock(&tcpfs_bpf_lock);
	list_for_each_entry(entry, &tcpfs_bpf_ops_list, list) {
		if (!entry->dead && !strcmp(entry->ops->name, name) &&
		    bpf_struct_ops_get(entry->ops)) {
			refcount_inc(&entry->refs);
			mutex_unlock(&tcpfs_bpf_lock);
			return entry;
		}
	}
	mutex_unlock(&tcpfs_bpf_lock);
	return NULL;
}

/**
 * tcpfs_bpf_get_wait() - Wait up to @timeout for a named provider to attach.
 * @name: mount-visible provider name
 * @timeout: wait budget in jiffies
 *
 * Return: a referenced provider entry, NULL on timeout, or an ERR_PTR.
 */
struct tcpfs_bpf_ops *tcpfs_bpf_get_wait(const char *name, unsigned long timeout)
{
	struct tcpfs_bpf_ops *entry;
	int seq;
	long ret;

	for (;;) {
		seq = atomic_read(&tcpfs_bpf_seq);
		entry = tcpfs_bpf_get(name);
		if (entry || !timeout)
			return entry;

		ret = wait_event_interruptible_timeout(tcpfs_bpf_wait,
						       atomic_read(&tcpfs_bpf_seq) != seq,
					timeout);
		if (ret < 0)
			return ERR_PTR(ret);
		if (!ret)
			return NULL;

		timeout = ret;
	}
}

/**
 * tcpfs_bpf_put() - Release a provider reference and retire it when detached.
 * @entry: provider reference
 *
 * Decrements the provider refcount and, when it reaches zero on a detached
 * entry, unlinks and frees it before releasing the struct_ops reference.
 */
void tcpfs_bpf_put(struct tcpfs_bpf_ops *entry)
{
	struct tcpfs_ops *ops;
	bool free_entry = false;

	if (!entry)
		return;
	ops = entry->ops;

	mutex_lock(&tcpfs_bpf_lock);
	if (refcount_dec_and_test(&entry->refs) && entry->dead) {
		list_del(&entry->list);
		free_entry = true;
	}
	mutex_unlock(&tcpfs_bpf_lock);

	if (free_entry)
		kfree(entry);
	bpf_struct_ops_put(ops);
}

/**
 * tcpfs_bpf_ops() - Return the immutable callback table for a provider.
 * @entry: provider reference
 */
const struct tcpfs_ops *tcpfs_bpf_ops(const struct tcpfs_bpf_ops *entry)
{
	return entry ? entry->ops : NULL;
}

/**
 * tcpfs_bpf_reg() - Validate and register a newly attached struct_ops provider.
 * @kdata: provider ops table
 * @link: struct_ops link being attached
 *
 * Return: 0 on success, or a negative errno.
 */
static int tcpfs_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct tcpfs_ops *ops = kdata;
	struct tcpfs_bpf_ops *entry, *iter;
	int ret = 0;

	if (!ops->name[0] || !ops->build_request || !ops->frame_tx ||
	    !ops->recv_response || !ops->unframe_rx || !ops->handle_response)
		return -EINVAL;
	if (!ops->conn_style)
		ops->conn_style = TCPFS_CONN_NEW;
	if (ops->conn_style < TCPFS_CONN_NEW ||
	    ops->conn_style > TCPFS_CONN_SERIAL)
		return -EINVAL;

	entry = kzalloc_obj(*entry, GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->ops = ops;
	refcount_set(&entry->refs, 1);

	mutex_lock(&tcpfs_bpf_lock);
	list_for_each_entry(iter, &tcpfs_bpf_ops_list, list) {
		if (!iter->dead && !strcmp(iter->ops->name, ops->name)) {
			ret = -EEXIST;
			break;
		}
	}
	if (!ret)
		list_add_tail(&entry->list, &tcpfs_bpf_ops_list);
	mutex_unlock(&tcpfs_bpf_lock);

	if (!ret) {
		atomic_inc(&tcpfs_bpf_seq);
		wake_up_all(&tcpfs_bpf_wait);
		pr_info("datafs: registered bpf ops=%s\n", ops->name);
	}

	if (ret)
		kfree(entry);
	return ret;
}

/**
 * tcpfs_bpf_unreg() - Detach a provider and retire it once unreferenced.
 * @kdata: provider ops table
 * @link: struct_ops link being detached
 */
static void tcpfs_bpf_unreg(void *kdata, struct bpf_link *link)
{
	struct tcpfs_ops *ops = kdata;
	struct tcpfs_bpf_ops *entry;

	mutex_lock(&tcpfs_bpf_lock);
	list_for_each_entry(entry, &tcpfs_bpf_ops_list, list) {
		if (entry->ops == ops) {
			pr_info("datafs: unregistering bpf ops=%s\n", ops->name);
			entry->dead = true;
			if (refcount_dec_and_test(&entry->refs)) {
				list_del(&entry->list);
				mutex_unlock(&tcpfs_bpf_lock);
				kfree(entry);
				return;
			}
			break;
		}
	}
	mutex_unlock(&tcpfs_bpf_lock);
}

/**
 * tcpfs_bpf_init_member() - Copy one non-callback ops field into kernel state.
 * @t: BTF type for the field
 * @ops: kernel ops table to populate
 * @src: provider field storage
 */
static int tcpfs_bpf_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	const struct tcpfs_ops *uops = udata;
	struct tcpfs_ops *kops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	if (moff == offsetof(struct tcpfs_ops, name)) {
		if (bpf_obj_name_cpy(kops->name, uops->name,
				     sizeof(kops->name)) <= 0)
			return -EINVAL;
		return 1;
	}
	if (moff == offsetof(struct tcpfs_ops, conn_style)) {
		kops->conn_style = uops->conn_style;
		return 1;
	}

	return 0;
}

/**
 * tcpfs_bpf_struct_ops_init() - Resolve callback-context BTF types.
 * @btf: BTF blob
 *
 * Return: 0 on success, or a negative errno.
 */
static int tcpfs_bpf_struct_ops_init(struct btf *btf)
{
	tcpfs_ctx_type = btf_type_by_id(btf, tcpfs_ctx_ids[0]);
	if (!tcpfs_ctx_type || tcpfs_ctx_type->size != sizeof(struct tcpfs_ctx))
		return -EINVAL;
	tcpfs_build_request_type =
		btf_type_by_id(btf, tcpfs_build_request_ids[0]);
	if (!tcpfs_build_request_type ||
	    tcpfs_build_request_type->size != sizeof(struct tcpfs_build_request_ctx))
		return -EINVAL;
	tcpfs_frame_tx_type = btf_type_by_id(btf, tcpfs_frame_tx_ids[0]);
	if (!tcpfs_frame_tx_type ||
	    tcpfs_frame_tx_type->size != sizeof(struct tcpfs_frame_tx_ctx))
		return -EINVAL;
	tcpfs_recv_response_type =
		btf_type_by_id(btf, tcpfs_recv_response_ids[0]);
	if (!tcpfs_recv_response_type ||
	    tcpfs_recv_response_type->size != sizeof(struct tcpfs_recv_response_ctx))
		return -EINVAL;
	tcpfs_unframe_rx_type =
		btf_type_by_id(btf, tcpfs_unframe_rx_ids[0]);
	if (!tcpfs_unframe_rx_type ||
	    tcpfs_unframe_rx_type->size != sizeof(struct tcpfs_unframe_rx_ctx))
		return -EINVAL;
	tcpfs_handle_response_type =
		btf_type_by_id(btf, tcpfs_handle_response_ids[0]);
	if (!tcpfs_handle_response_type ||
	    tcpfs_handle_response_type->size !=
		    sizeof(struct tcpfs_handle_response_ctx))
		return -EINVAL;
	tcpfs_loan_socket_type = btf_type_by_id(btf, tcpfs_loan_socket_ids[0]);
	if (!tcpfs_loan_socket_type ||
	    tcpfs_loan_socket_type->size != sizeof(struct tcpfs_loan_socket_ctx))
		return -EINVAL;
	tcpfs_return_socket_type =
		btf_type_by_id(btf, tcpfs_return_socket_ids[0]);
	if (!tcpfs_return_socket_type ||
	    tcpfs_return_socket_type->size !=
		    sizeof(struct tcpfs_return_socket_ctx))
		return -EINVAL;
	tcpfs_socket_loan_type = btf_type_by_id(btf, tcpfs_socket_loan_ids[0]);
	if (!tcpfs_socket_loan_type ||
	    tcpfs_socket_loan_type->size != sizeof(struct tcpfs_socket_loan))
		return -EINVAL;

	return 0;
}

/**
 * tcpfs_bpf_btf_get_ctx_type() - Expose the standard struct_ops helper types.
 */
static const struct bpf_func_proto *
tcpfs_bpf_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

/**
 * tcpfs_bpf_write_in_range() - Whether a BPF write fits a mutable field.
 * @off, @size: write extent
 * @start, @end: target field extent
 */
static bool tcpfs_bpf_write_in_range(int off, int size, size_t start,
				     size_t end)
{
	if (off < 0 || size < 0 || (size_t)off < start || (size_t)off > end)
		return false;

	return (size_t)size <= end - off;
}

/**
 * tcpfs_bpf_btf_struct_access() - Restrict BPF writes to output fields.
 */
static int tcpfs_bpf_btf_struct_access(struct bpf_verifier_log *log,
				       const struct bpf_reg_state *reg,
				       int off, int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	/*
	 * LLVM may fold &callback->output accesses back into the callback base.
	 * Translate those writes to the nested mutable object before applying the
	 * field allowlist.  Offsets into the input pointer remain negative after
	 * translation and are therefore rejected below.
	 */
	if (t == tcpfs_build_request_type) {
		off -= offsetof(struct tcpfs_build_request_ctx, output);
		t = tcpfs_ctx_type;
	} else if (t == tcpfs_frame_tx_type) {
		off -= offsetof(struct tcpfs_frame_tx_ctx, output);
		t = tcpfs_ctx_type;
	} else if (t == tcpfs_recv_response_type) {
		off -= offsetof(struct tcpfs_recv_response_ctx, output);
		t = tcpfs_ctx_type;
	} else if (t == tcpfs_handle_response_type) {
		off -= offsetof(struct tcpfs_handle_response_ctx, output);
		t = tcpfs_ctx_type;
	} else if (t == tcpfs_loan_socket_type) {
		off -= offsetof(struct tcpfs_loan_socket_ctx, output);
		t = tcpfs_socket_loan_type;
	} else if (t == tcpfs_return_socket_type) {
		off -= offsetof(struct tcpfs_return_socket_ctx, output);
		t = tcpfs_socket_loan_type;
	}
	if (t == tcpfs_socket_loan_type) {
		if (tcpfs_bpf_write_in_range(off, size,
					     offsetof(struct tcpfs_socket_loan,
						      socket_key),
					     offsetofend(struct tcpfs_socket_loan,
							 socket_key)))
			return 0;
		bpf_log(log, "unsupported tcpfs_socket_loan write at off %d size %d\n",
			off, size);
		return -EACCES;
	}
	if (t == tcpfs_unframe_rx_type) {
		bpf_log(log, "tcpfs_unframe_rx_ctx is read-only\n");
		return -EACCES;
	}
	if (t != tcpfs_ctx_type) {
		bpf_log(log, "only tcpfs callback context writes are supported\n");
		return -EACCES;
	}

	if (tcpfs_bpf_write_in_range(off, size,
				     offsetof(struct tcpfs_ctx, payload_len),
				     offsetofend(struct tcpfs_ctx, payload_len)) ||
	    tcpfs_bpf_write_in_range(off, size,
				     offsetof(struct tcpfs_ctx, frame_len),
				     offsetofend(struct tcpfs_ctx, frame_len)) ||
	    tcpfs_bpf_write_in_range(off, size,
				     offsetof(struct tcpfs_ctx, rx_need),
				     offsetofend(struct tcpfs_ctx, rx_need)) ||
	    tcpfs_bpf_write_in_range(off, size,
				     offsetof(struct tcpfs_ctx, payload),
				     offsetofend(struct tcpfs_ctx, payload)) ||
	    tcpfs_bpf_write_in_range(off, size,
				     offsetof(struct tcpfs_ctx, result),
				     offsetofend(struct tcpfs_ctx, result)))
		return 0;

	bpf_log(log, "write access at off %d with size %d is not supported\n",
		off, size);
	return -EACCES;
}

/**
 * tcpfs_bpf_validate_ctx() - Validate callback context after each invocation.
 * @ctx: callback context
 *
 * Return: 0 on success, or a negative errno.
 */
int tcpfs_bpf_validate_ctx(const struct tcpfs_ctx *ctx)
{
	const struct tcpfs_result *result;
	const struct tcpfs_rx_run *run;

	if (!ctx || ctx->payload_len > sizeof(ctx->payload) ||
	    ctx->rx_len > sizeof(ctx->rx) || ctx->frame_len > ctx->rx_len ||
	    ctx->rx_need > sizeof(ctx->rx))
		return -EPROTO;

	result = &ctx->result;
	if (result->type > TCPFS_RESULT_CONTINUE ||
	    result->flags & ~TCPFS_RESULT_F_MASK ||
	    result->payload_len > sizeof(result->payload))
		return -EPROTO;

	if (result->type == TCPFS_RESULT_ERROR) {
		if (result->error >= 0)
			return -EPROTO;
	} else if (result->error) {
		return -EPROTO;
	}

	run = &result->rx_run;
	if (run->data_len || run->wire_len || run->rx_offset || run->flags) {
		if (result->type != TCPFS_RESULT_DATA ||
		    run->flags & ~TCPFS_RX_RUN_F_MASK ||
		    run->wire_len < run->data_len ||
		    run->data_len > ctx->len ||
		    run->rx_offset > ctx->rx_len ||
		    result->payload_len > run->data_len ||
		    result->payload_len > ctx->rx_len - run->rx_offset)
			return -EPROTO;
	}

	if (result->flags & TCPFS_RESULT_F_SIZE_VALID &&
	    result->type != TCPFS_RESULT_ATTR &&
	    result->type != TCPFS_RESULT_DATA)
		return -EPROTO;
	if (result->type == TCPFS_RESULT_CONTINUE &&
	    (result->id != ctx->id || !ctx->payload_len ||
	     result->payload_len || result->flags ||
	     result->ino || result->size || result->offset || result->mode ||
	     run->data_len || run->wire_len || run->rx_offset || run->flags))
		return -EPROTO;

	return 0;
}

static const struct bpf_verifier_ops tcpfs_bpf_verifier_ops = {
	.get_func_proto		= tcpfs_bpf_func_proto,
	.is_valid_access	= bpf_tracing_btf_ctx_access,
	.btf_struct_access	= tcpfs_bpf_btf_struct_access,
};

/** CFI-compatible default for the request builder. */
static int tcpfs_build_stub(struct tcpfs_build_request_ctx *ctx)
{
	return -EOPNOTSUPP;
}

/** CFI-compatible default for the request framer. */
static int tcpfs_frame_stub(struct tcpfs_frame_tx_ctx *ctx)
{
	return -EOPNOTSUPP;
}

/** CFI-compatible default for response classification. */
static int tcpfs_recv_stub(struct tcpfs_recv_response_ctx *ctx)
{
	return -EOPNOTSUPP;
}

/**
 * tcpfs_unframe_stub() - CFI-compatible default for the receive framer.
 */
static int tcpfs_unframe_stub(const struct tcpfs_unframe_rx_ctx *ctx)
{
	return -EOPNOTSUPP;
}

/** CFI-compatible default for response decoding. */
static int tcpfs_handle_stub(struct tcpfs_handle_response_ctx *ctx)
{
	return -EOPNOTSUPP;
}

/** CFI-compatible default for socket loans. */
static int tcpfs_loan_ctx_stub(struct tcpfs_loan_socket_ctx *ctx)
{
	return -EOPNOTSUPP;
}

/** CFI-compatible default for socket returns. */
static void tcpfs_return_ctx_stub(struct tcpfs_return_socket_ctx *ctx)
{
}

static struct tcpfs_ops tcpfs_cfi_stubs = {
	.build_request		= tcpfs_build_stub,
	.frame_tx		= tcpfs_frame_stub,
	.recv_response		= tcpfs_recv_stub,
	.unframe_rx		= tcpfs_unframe_stub,
	.handle_response	= tcpfs_handle_stub,
	.loan_socket		= tcpfs_loan_ctx_stub,
	.return_socket		= tcpfs_return_ctx_stub,
};

static struct bpf_struct_ops tcpfs_bpf_struct_ops = {
	.verifier_ops	= &tcpfs_bpf_verifier_ops,
	.init		= tcpfs_bpf_struct_ops_init,
	.reg		= tcpfs_bpf_reg,
	.unreg		= tcpfs_bpf_unreg,
	.init_member	= tcpfs_bpf_init_member,
	.cfi_stubs	= &tcpfs_cfi_stubs,
	.name		= "tcpfs_ops",
	.owner		= THIS_MODULE,
};

/**
 * tcpfs_bpf_init() - Register datafs kfuncs and the shared struct_ops type.
 *
 * Return: 0 on success, or a negative errno.
 */
int tcpfs_bpf_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&tcpfs_kfunc_set);
	if (ret)
		return ret;

	return register_bpf_struct_ops(&tcpfs_bpf_struct_ops, tcpfs_ops);
}

/**
 * tcpfs_bpf_exit() - Lifecycle hook for struct_ops teardown.
 */
void tcpfs_bpf_exit(void)
{
}
