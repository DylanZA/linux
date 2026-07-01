// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "tcpfs.h"

static DEFINE_MUTEX(tcpfs_bpf_lock);
static atomic_t tcpfs_bpf_seq = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(tcpfs_bpf_wait);
static LIST_HEAD(tcpfs_bpf_ops_list);

struct tcpfs_bpf_ops *tcpfs_bpf_get(const char *name)
{
	struct tcpfs_bpf_ops *entry;

	mutex_lock(&tcpfs_bpf_lock);
	list_for_each_entry(entry, &tcpfs_bpf_ops_list, list) {
		if (!entry->dead && !strcmp(entry->ops->name, name)) {
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
				atomic_read(&tcpfs_bpf_seq) != seq, timeout);
		if (ret < 0)
			return ERR_PTR(ret);
		if (!ret)
			return NULL;

		timeout = ret;
	}
}

void tcpfs_bpf_put(struct tcpfs_bpf_ops *entry)
{
	if (!entry)
		return;

	mutex_lock(&tcpfs_bpf_lock);
	if (refcount_dec_and_test(&entry->refs) && entry->dead) {
		list_del(&entry->list);
		mutex_unlock(&tcpfs_bpf_lock);
		kfree(entry);
		return;
	}
	mutex_unlock(&tcpfs_bpf_lock);
}

static int tcpfs_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct tcpfs_ops *ops = kdata;
	struct tcpfs_bpf_ops *entry, *iter;
	int ret = 0;

	if (!ops->name[0] || !ops->build_request || !ops->frame_tx ||
	    !ops->unframe_rx || !ops->handle_response)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
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
	return register_bpf_struct_ops(&tcpfs_bpf_struct_ops, tcpfs_ops);
}

void tcpfs_bpf_exit(void)
{
}
