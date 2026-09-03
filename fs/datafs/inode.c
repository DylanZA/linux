// SPDX-License-Identifier: GPL-2.0
#include <linux/namei.h>
#include <linux/slab.h>

#include "datafs.h"

/**
 * datafs_build_child_path() - Construct a root-relative child path.
 * @dir: parent inode whose path prefixes the child
 * @name: child name
 * @buf: destination buffer
 * @buflen: size of @buf
 *
 * Return: the formatted length, or a negative errno if the path does not fit.
 */
static int datafs_build_child_path(struct inode *dir,
				   const struct qstr *name, char *buf,
				   size_t buflen)
{
	const struct datafs_inode_info *parent = DATAFS_I(dir);
	int name_len = name->len;

	if (!parent->path || !parent->path[0])
		return snprintf(buf, buflen, "%.*s", name_len, name->name);

	return snprintf(buf, buflen, "%s/%.*s", parent->path, name_len,
			name->name);
}

/**
 * datafs_get_inode() - Allocate and initialize an inode.
 * @sb: owning superblock
 * @dir: parent inode (may be NULL for the root)
 * @mode: inode mode (force-normalized read-only)
 * @path: root-relative inode path
 * @ino: remote inode number (0 picks the provider-generated number)
 * @size: initial file size
 *
 * Initializes the netfs inode and assigns the provider-appropriate inode
 * operations for the requested mode.
 *
 * Return: the allocated inode, or NULL on allocation failure.
 */
struct inode *datafs_get_inode(struct super_block *sb, const struct inode *dir,
			       umode_t mode, const char *path, u64 ino,
			       u64 size)
{
	struct datafs_inode_info *di;
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return NULL;

	di = DATAFS_I(inode);
	di->remote_ino = ino ?: inode->i_ino;
	di->path = kstrdup(path ?: "", GFP_KERNEL);
	if (!di->path) {
		iput(inode);
		return NULL;
	}

	inode->i_ino = di->remote_ino ?: get_next_ino();
	mode &= ~0222;
	inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
	simple_inode_init_ts(inode);
	i_size_write(inode, size);
	netfs_inode_init(&di->netfs, &datafs_netfs_ops, false);

	if (S_ISDIR(mode)) {
		inode->i_op = &datafs_dir_iops;
		inode->i_fop = &datafs_dir_fops;
		set_nlink(inode, 2);
	} else if (S_ISREG(mode)) {
		inode->i_op = &datafs_file_iops;
		inode->i_fop = &datafs_file_fops;
		inode->i_mapping->a_ops = &datafs_aops;
		set_nlink(inode, 1);
	} else {
		init_special_inode(inode, mode, 0);
	}

	return inode;
}

/**
 * datafs_inode_from_result() - Convert provider metadata into a VFS inode.
 * @sb: owning superblock
 * @dir: parent inode (may be NULL for the root)
 * @path: root-relative inode path
 * @res: validated provider result
 * @inodep: returns the allocated inode
 *
 * Validates the mode and size from the result and allocates a datafs inode.
 *
 * Return: 0 on success (with *inodep set), or a negative errno.
 */
static int datafs_inode_from_result(struct super_block *sb,
				    const struct inode *dir,
				    const char *path,
				    const struct tcpfs_result *res,
				    struct inode **inodep)
{
	umode_t mode = res->mode;

	if (res->size > (u64)MAX_LFS_FILESIZE)
		return -EFBIG;
	if (res->mode & ~((u32)S_IFMT | S_IALLUGO))
		return -EPROTO;
	if (!mode)
		mode = S_IFREG | 0444;
	if (!S_ISDIR(mode) && !S_ISREG(mode))
		return -EOPNOTSUPP;

	*inodep = datafs_get_inode(sb, dir, mode, path, res->ino, res->size);
	return *inodep ? 0 : -ENOMEM;
}

/**
 * datafs_lookup() - Resolve a child name through the protocol lookup.
 * @parent inode: dir
 * @dentry: dentry for the child name
 * @flags: lookup flags
 *
 * Issues a LOOKUP and, when the provider reports an entry, allocates the
 * inode. A not-found result creates a negative dentry.
 *
 * Return: NULL on success, or an ERR_PTR.
 */
static struct dentry *datafs_lookup(struct inode *dir, struct dentry *dentry,
				    unsigned int flags)
{
	struct datafs_sb_info *sbi = DATAFS_SB(dir->i_sb);
	struct tcpfs_ctx *ctx;
	struct inode *inode = NULL;
	char path[TCPFS_PATH_MAX];
	int len;
	int ret;

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	len = datafs_build_child_path(dir, &dentry->d_name, path,
				      sizeof(path));
	if (len < 0 || len >= sizeof(path))
		return ERR_PTR(-ENAMETOOLONG);

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->op = TCPFS_OP_LOOKUP;
	ctx->parent_ino = DATAFS_I(dir)->remote_ino;
	ctx->id = atomic64_inc_return(&sbi->next_id);
	ctx->path_len = len;
	memcpy(ctx->path, path, len + 1);

	ret = datafs_call(sbi, ctx);
	if (!ret)
		ret = ctx->result.error;
	if (!ret && ctx->result.type != TCPFS_RESULT_ATTR)
		ret = -EIO;
	if (!ret)
		ret = datafs_inode_from_result(dir->i_sb, dir, path,
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

/**
 * datafs_getattr() - Refresh inode attributes through the provider.
 * @idmap: mount idmap
 * @path: path of the inode being queried
 * @stat: stat result to fill
 * @request_mask: attribute fields requested
 * @query_flags: query flags
 *
 * Issues a GETATTR callback, validates the returned size/mode against the
 * inode, and fills @stat.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_getattr(struct mnt_idmap *idmap, const struct path *path,
			  struct kstat *stat, u32 request_mask,
			  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct datafs_inode_info *di = DATAFS_I(inode);
	struct datafs_sb_info *sbi = DATAFS_SB(inode->i_sb);
	struct tcpfs_ctx *ctx;
	ssize_t path_len;
	int ret;

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->op = TCPFS_OP_GETATTR;
	ctx->ino = di->remote_ino;
	ctx->id = atomic64_inc_return(&sbi->next_id);
	path_len = strscpy(ctx->path, di->path ?: "", sizeof(ctx->path));
	if (path_len < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	ctx->path_len = path_len;

	ret = datafs_call(sbi, ctx);
	if (!ret)
		ret = ctx->result.error;
	if (!ret && ctx->result.type != TCPFS_RESULT_ATTR)
		ret = -EIO;
	if (!ret && ctx->result.size > (u64)MAX_LFS_FILESIZE)
		ret = -EFBIG;
	if (!ret && ctx->result.mode & ~((u32)S_IFMT | S_IALLUGO))
		ret = -EPROTO;
	if (!ret && ctx->result.mode &&
	    (ctx->result.mode & S_IFMT) != (inode->i_mode & S_IFMT))
		ret = -EIO;
	if (!ret) {
		if (ctx->result.flags & TCPFS_RESULT_F_SIZE_VALID ||
		    ctx->result.size)
			netfs_resize_file(&di->netfs, ctx->result.size, true);
		if (ctx->result.mode)
			inode->i_mode = (inode->i_mode & S_IFMT) |
				(ctx->result.mode & S_IALLUGO & ~0222);
	}
out:
	kfree(ctx);
	if (ret)
		return ret;

	generic_fillattr(idmap, request_mask, inode, stat);
	return 0;
}

const struct inode_operations datafs_dir_iops = {
	.lookup		= datafs_lookup,
	.getattr	= datafs_getattr,
};

const struct inode_operations datafs_file_iops = {
	.getattr	= datafs_getattr,
};
