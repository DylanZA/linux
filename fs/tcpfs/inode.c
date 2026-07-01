// SPDX-License-Identifier: GPL-2.0
#include <linux/namei.h>
#include <linux/slab.h>

#include "tcpfs.h"

static int tcpfs_build_child_path(const struct inode *dir,
				  const struct qstr *name, char *buf,
				  size_t buflen)
{
	const struct tcpfs_inode_info *parent = TCPFS_I((struct inode *)dir);

	if (!parent->path || !parent->path[0])
		return snprintf(buf, buflen, "%.*s", name->len, name->name);

	return snprintf(buf, buflen, "%s/%.*s", parent->path, name->len,
			name->name);
}

struct inode *tcpfs_get_inode(struct super_block *sb, const struct inode *dir,
			      umode_t mode, const char *path, u64 ino,
			      u64 size)
{
	struct tcpfs_inode_info *ti;
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return NULL;

	ti = TCPFS_I(inode);
	ti->remote_ino = ino ?: inode->i_ino;
	ti->path = kstrdup(path ?: "", GFP_KERNEL);
	if (!ti->path) {
		iput(inode);
		return NULL;
	}

	inode->i_ino = ti->remote_ino ?: get_next_ino();
	inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
	simple_inode_init_ts(inode);
	inode->i_size = size;

	if (S_ISDIR(mode)) {
		inode->i_op = &tcpfs_dir_iops;
		inode->i_fop = &tcpfs_dir_fops;
		set_nlink(inode, 2);
	} else if (S_ISREG(mode)) {
		inode->i_op = &tcpfs_file_iops;
		inode->i_fop = &tcpfs_file_fops;
		set_nlink(inode, 1);
	} else {
		init_special_inode(inode, mode, 0);
	}

	return inode;
}

static int tcpfs_inode_from_result(struct super_block *sb,
				   const struct inode *dir,
				   const char *path,
				   const struct tcpfs_result *res,
				   struct inode **inodep)
{
	umode_t mode = res->mode;

	if (!mode)
		mode = S_IFREG | 0444;
	if (!S_ISDIR(mode) && !S_ISREG(mode))
		return -EOPNOTSUPP;

	*inodep = tcpfs_get_inode(sb, dir, mode, path, res->ino, res->size);
	return *inodep ? 0 : -ENOMEM;
}

static struct dentry *tcpfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct tcpfs_sb_info *sbi = TCPFS_SB(dir->i_sb);
	struct tcpfs_ctx *ctx;
	struct inode *inode = NULL;
	char path[TCPFS_PATH_MAX];
	int len, ret;

	if (dentry->d_name.len >= NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	len = tcpfs_build_child_path(dir, &dentry->d_name, path, sizeof(path));
	if (len < 0 || len >= sizeof(path))
		return ERR_PTR(-ENAMETOOLONG);

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->op = TCPFS_OP_LOOKUP;
	ctx->parent_ino = TCPFS_I(dir)->remote_ino;
	ctx->id = atomic64_inc_return(&sbi->next_id);
	ctx->path_len = len;
	memcpy(ctx->path, path, len + 1);

	ret = tcpfs_call(sbi, ctx);
	if (!ret)
		ret = ctx->result.error;
	if (!ret && ctx->result.type == TCPFS_RESULT_ATTR)
		ret = tcpfs_inode_from_result(dir->i_sb, dir, path,
					      &ctx->result, &inode);
	kfree(ctx);

	if (ret == -ENOENT) {
		d_add(dentry, NULL);
		return NULL;
	}
	if (ret)
		return ERR_PTR(ret);

	d_add(dentry, inode);
	return NULL;
}

static int tcpfs_getattr(struct mnt_idmap *idmap,
			 const struct path *path, struct kstat *stat,
			 u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct tcpfs_inode_info *ti = TCPFS_I(inode);
	struct tcpfs_sb_info *sbi = TCPFS_SB(inode->i_sb);
	struct tcpfs_ctx *ctx;
	int ret;

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->op = TCPFS_OP_GETATTR;
	ctx->ino = ti->remote_ino;
	ctx->id = atomic64_inc_return(&sbi->next_id);
	strscpy(ctx->path, ti->path ?: "", sizeof(ctx->path));
	ctx->path_len = strlen(ctx->path);

	ret = tcpfs_call(sbi, ctx);
	if (!ret)
		ret = ctx->result.error;
	if (!ret && ctx->result.type == TCPFS_RESULT_ATTR) {
		if (ctx->result.flags & TCPFS_RESULT_F_SIZE_VALID ||
		    ctx->result.size)
			i_size_write(inode, ctx->result.size);
		if (ctx->result.mode)
			inode->i_mode = ctx->result.mode;
	}
	kfree(ctx);
	if (ret)
		return ret;

	generic_fillattr(idmap, request_mask, inode, stat);
	return 0;
}

const struct inode_operations tcpfs_dir_iops = {
	.lookup		= tcpfs_lookup,
	.getattr	= tcpfs_getattr,
};

const struct inode_operations tcpfs_file_iops = {
	.getattr	= tcpfs_getattr,
};
