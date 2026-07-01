// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "tcpfs.h"

static DEFINE_MUTEX(tcpfs_bpf_lock);
static atomic_t tcpfs_bpf_seq = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(tcpfs_bpf_wait);
static LIST_HEAD(tcpfs_bpf_ops_list);

__bpf_kfunc_start_defs();

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

__bpf_kfunc int bpf_tcpfs_payload_append_str(struct tcpfs_ctx *ctx,
					     const char *src__str)
{
	if (!src__str)
		return -EINVAL;

	return bpf_tcpfs_payload_append(ctx, src__str, strlen(src__str));
}

__bpf_kfunc int bpf_tcpfs_payload_append_mount_arg(struct tcpfs_ctx *ctx)
{
	u32 len;

	if (!ctx)
		return -EINVAL;
	len = min_t(u32, ctx->mount_arg_len, sizeof(ctx->mount_arg));
	return bpf_tcpfs_payload_append(ctx, ctx->mount_arg, len);
}

__bpf_kfunc int bpf_tcpfs_payload_append_path(struct tcpfs_ctx *ctx)
{
	u32 len;

	if (!ctx)
		return -EINVAL;
	len = min_t(u32, ctx->path_len, sizeof(ctx->path));
	return bpf_tcpfs_payload_append(ctx, ctx->path, len);
}

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

__bpf_kfunc int bpf_tcpfs_ctx_read_byte(struct tcpfs_ctx *ctx, u32 offset)
{
	if (!ctx || offset >= sizeof(*ctx))
		return -EINVAL;

	return *((u8 *)ctx + offset);
}

__bpf_kfunc s64 bpf_tcpfs_ctx_read_be32(struct tcpfs_ctx *ctx, u32 offset)
{
	const u8 *p;

	if (!ctx || offset > sizeof(*ctx) - sizeof(u32))
		return -EINVAL;
	p = (u8 *)ctx + offset;

	return (u32)p[0] << 24 | (u32)p[1] << 16 |
	       (u32)p[2] << 8 | p[3];
}

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

__bpf_kfunc int bpf_tcpfs_rx_find(struct tcpfs_ctx *ctx, const void *needle,
				  u32 needle__sz)
{
	return bpf_tcpfs_rx_find_from(ctx, 0, needle, needle__sz);
}

__bpf_kfunc int bpf_tcpfs_rx_find_str_from(struct tcpfs_ctx *ctx, u32 offset,
					   const char *needle__str)
{
	if (!needle__str)
		return -EINVAL;

	return bpf_tcpfs_rx_find_from(ctx, offset, needle__str,
				      strlen(needle__str));
}

__bpf_kfunc int bpf_tcpfs_rx_find_str(struct tcpfs_ctx *ctx,
				      const char *needle__str)
{
	if (!needle__str)
		return -EINVAL;

	return bpf_tcpfs_rx_find(ctx, needle__str, strlen(needle__str));
}

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
BTF_ID_FLAGS(func, bpf_tcpfs_result_append)
BTF_ID_FLAGS(func, bpf_tcpfs_result_append_rx)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_find_from)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_find)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_find_str_from)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_find_str)
BTF_ID_FLAGS(func, bpf_tcpfs_rx_parse_u64)
BTF_KFUNCS_END(tcpfs_kfunc_set_ids)

static const struct btf_kfunc_id_set tcpfs_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &tcpfs_kfunc_set_ids,
};

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

static int tcpfs_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct tcpfs_ops *ops = kdata;
	struct tcpfs_bpf_ops *entry, *iter;
	int ret = 0;

	if (!ops->name[0] || !ops->build_request || !ops->frame_tx ||
	    !ops->unframe_rx || !ops->handle_response)
		return -EINVAL;
	if (!ops->conn_style)
		ops->conn_style = TCPFS_CONN_NEW;
	if (ops->conn_style < TCPFS_CONN_NEW ||
	    ops->conn_style > TCPFS_CONN_OVERLAP)
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
		pr_info("tcpfs: registered bpf ops=%s\n", ops->name);
	}

	if (ret)
		kfree(entry);
	return ret;
}

static void tcpfs_bpf_unreg(void *kdata, struct bpf_link *link)
{
	struct tcpfs_ops *ops = kdata;
	struct tcpfs_bpf_ops *entry;

	mutex_lock(&tcpfs_bpf_lock);
	list_for_each_entry(entry, &tcpfs_bpf_ops_list, list) {
		if (entry->ops == ops) {
			pr_info("tcpfs: unregistering bpf ops=%s\n", ops->name);
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

static int tcpfs_bpf_struct_ops_init(struct btf *btf)
{
	return 0;
}

static const struct bpf_func_proto *
tcpfs_bpf_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static int tcpfs_bpf_btf_struct_access(struct bpf_verifier_log *log,
				       const struct bpf_reg_state *reg,
				       int off, int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (!t || !btf_type_is_struct(t) || t->size != sizeof(struct tcpfs_ctx)) {
		bpf_log(log, "only tcpfs_ctx writes are supported\n");
		return -EACCES;
	}

	if (off < 0 || off + size > sizeof(struct tcpfs_ctx)) {
		bpf_log(log, "write access at off %d with size %d\n", off, size);
		return -EACCES;
	}

	return 0;
}

static const struct bpf_verifier_ops tcpfs_bpf_verifier_ops = {
	.get_func_proto		= tcpfs_bpf_func_proto,
	.is_valid_access	= bpf_tracing_btf_ctx_access,
	.btf_struct_access	= tcpfs_bpf_btf_struct_access,
};

static int tcpfs_stub(struct tcpfs_ctx *ctx)
{
	return -EOPNOTSUPP;
}

static struct tcpfs_ops tcpfs_cfi_stubs = {
	.build_request		= tcpfs_stub,
	.frame_tx		= tcpfs_stub,
	.unframe_rx		= tcpfs_stub,
	.handle_response	= tcpfs_stub,
	.on_unsolicited		= tcpfs_stub,
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

int tcpfs_bpf_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&tcpfs_kfunc_set);
	if (ret)
		return ret;

	return register_bpf_struct_ops(&tcpfs_bpf_struct_ops, tcpfs_ops);
}

void tcpfs_bpf_exit(void)
{
}
