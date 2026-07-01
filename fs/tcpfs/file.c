// SPDX-License-Identifier: GPL-2.0
#include <linux/uio.h>

#include "tcpfs.h"

static int tcpfs_open(struct inode *inode, struct file *file)
{
	if (!S_ISREG(inode->i_mode))
		return 0;
	file->f_mode |= FMODE_CAN_ODIRECT;
	return 0;
}

static ssize_t tcpfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct tcpfs_inode_info *ti = TCPFS_I(inode);
	struct tcpfs_sb_info *sbi = TCPFS_SB(inode->i_sb);
	struct tcpfs_ctx *ctx;
	loff_t size = i_size_read(inode);
	size_t want = iov_iter_count(to);
	ssize_t ret;

	if (!want)
		return 0;
	if (iocb->ki_pos >= size)
		return 0;
	want = min_t(size_t, want, TCPFS_PAYLOAD_MAX);
	want = min_t(size_t, want, size - iocb->ki_pos);

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->op = TCPFS_OP_READ;
	ctx->ino = ti->remote_ino;
	ctx->id = atomic64_inc_return(&sbi->next_id);
	ctx->offset = iocb->ki_pos;
	ctx->len = want;
	strscpy(ctx->path, ti->path ?: "", sizeof(ctx->path));
	ctx->path_len = strlen(ctx->path);

	ret = tcpfs_call(sbi, ctx);
	if (!ret)
		ret = ctx->result.error;
	if (!ret && ctx->result.type != TCPFS_RESULT_DATA)
		ret = -EIO;
	if (!ret) {
		size_t n = min_t(size_t, ctx->result.payload_len, want);

		if (copy_to_iter(ctx->result.payload, n, to) != n)
			ret = -EFAULT;
		else {
			iocb->ki_pos += n;
			ret = n;
		}
	}

	kfree(ctx);
	return ret;
}

static bool tcpfs_emit_payload_dirents(struct dir_context *ctx,
				       const struct tcpfs_result *res)
{
	const char *p = res->payload;
	size_t left = strnlen(res->payload, res->payload_len);

	while (left) {
		const char *nl = memchr(p, '\n', left);
		size_t len = nl ? (size_t)(nl - p) : left;
		unsigned int type = DT_REG;

		if (len && p[len - 1] == '/') {
			type = DT_DIR;
			len--;
		}
		if (len && !dir_emit(ctx, p, len, get_next_ino(), type))
			return false;
		if (!nl)
			break;
		left -= len + 1;
		p = nl + 1;
	}
	return true;
}

static int tcpfs_iterate_shared(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct tcpfs_inode_info *ti = TCPFS_I(inode);
	struct tcpfs_sb_info *sbi = TCPFS_SB(inode->i_sb);
	struct tcpfs_ctx *tctx;
	int ret;

	if (ctx->pos == 0 && !dir_emit_dots(file, ctx))
		return 0;
	if (ctx->pos > 2)
		return 0;

	tctx = kzalloc(sizeof(*tctx), GFP_KERNEL);
	if (!tctx)
		return -ENOMEM;

	tctx->op = TCPFS_OP_READDIR;
	tctx->ino = ti->remote_ino;
	tctx->id = atomic64_inc_return(&sbi->next_id);
	tctx->offset = ctx->pos;
	strscpy(tctx->path, ti->path ?: "", sizeof(tctx->path));
	tctx->path_len = strlen(tctx->path);

	ret = tcpfs_call(sbi, tctx);
	if (!ret)
		ret = tctx->result.error;
	if (!ret && tctx->result.type != TCPFS_RESULT_DIRENT)
		ret = -EIO;
	if (!ret && tcpfs_emit_payload_dirents(ctx, &tctx->result))
		ctx->pos = 3;

	kfree(tctx);
	return ret;
}

const struct file_operations tcpfs_file_fops = {
	.open		= tcpfs_open,
	.read_iter	= tcpfs_read_iter,
	.llseek		= generic_file_llseek,
};

const struct file_operations tcpfs_dir_fops = {
	.iterate_shared	= tcpfs_iterate_shared,
	.llseek		= generic_file_llseek,
};
