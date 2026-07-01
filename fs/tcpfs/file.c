// SPDX-License-Identifier: GPL-2.0
#include <linux/io_uring/cmd.h>
#include <linux/uio.h>
#include <uapi/linux/tcpfs.h>

#include "tcpfs.h"

static int tcpfs_open(struct inode *inode, struct file *file)
{
	if (!S_ISREG(inode->i_mode))
		return 0;
	if (file->f_mode & FMODE_WRITE)
		return -EROFS;
	file->f_mode |= FMODE_CAN_ODIRECT;
	file->f_mode &= ~FMODE_WRITE;
	return 0;
}

static ssize_t tcpfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct tcpfs_inode_info *ti = TCPFS_I(inode);
	struct tcpfs_sb_info *sbi = TCPFS_SB(inode->i_sb);
	loff_t size = i_size_read(inode);
	size_t orig_count;
	size_t want = iov_iter_count(to);
	ssize_t ret;

	if (!want)
		return 0;
	if (iocb->ki_pos >= size)
		return 0;
	want = min_t(size_t, want, size - iocb->ki_pos);
	orig_count = iov_iter_count(to);
	iov_iter_truncate(to, want);

	ret = tcpfs_read_to_iter(sbi, ti->path ?: "", strlen(ti->path ?: ""),
				 ti->remote_ino, iocb->ki_pos, want, to);
	iov_iter_reexpand(to, orig_count - max_t(ssize_t, ret, 0));
	if (ret > 0)
		iocb->ki_pos += ret;

	return ret;
}

static int tcpfs_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	const struct io_uring_sqe *sqe = cmd->sqe;
	struct file *file = cmd->file;
	struct inode *inode = file_inode(file);
	struct tcpfs_inode_info *ti = TCPFS_I(inode);
	struct tcpfs_sb_info *sbi = TCPFS_SB(inode->i_sb);
	loff_t size = i_size_read(inode);
	u64 offset;
	u32 ifq_idx;
	size_t len;

	if (unlikely(issue_flags & IO_URING_F_CANCEL))
		return tcpfs_cancel_zc_async(cmd);
	if (cmd->cmd_op != TCPFS_URING_CMD_READ_ZC)
		return -EOPNOTSUPP;
	if (!S_ISREG(inode->i_mode))
		return -EINVAL;
	if (!(file->f_flags & O_DIRECT))
		return -EINVAL;

	if (sqe->ioprio || sqe->__pad1 || sqe->addr || sqe->__pad2[0] ||
	    cmd->flags)
		return -EINVAL;

	offset = READ_ONCE(sqe->addr3);
	ifq_idx = READ_ONCE(sqe->zcrx_ifq_idx);
	len = READ_ONCE(sqe->len);
	if (offset >= size && size)
		return 0;
	if (!len)
		return 0;

	return tcpfs_read_zc_async(sbi, ti->path ?: "",
				   strlen(ti->path ?: ""), ti->remote_ino,
				   offset, len, ifq_idx, cmd, issue_flags);
}

static bool tcpfs_emit_payload_dirents(struct dir_context *ctx,
				       const struct tcpfs_result *res)
{
	const char *p = res->payload;
	size_t left = strnlen(res->payload, res->payload_len);

	while (left) {
		const char *nl = memchr(p, '\n', left);
		size_t record_len = nl ? (size_t)(nl - p) : left;
		size_t len = record_len;
		unsigned int type = DT_REG;

		if (len && p[len - 1] == '/') {
			type = DT_DIR;
			len--;
		}
		if (len && !dir_emit(ctx, p, len, get_next_ino(), type))
			return false;
		if (!nl)
			break;
		left -= record_len + 1;
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

	tctx = kzalloc_obj(*tctx, GFP_KERNEL);
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
	.uring_cmd	= tcpfs_uring_cmd,
	.llseek		= generic_file_llseek,
};

const struct file_operations tcpfs_dir_fops = {
	.iterate_shared	= tcpfs_iterate_shared,
	.llseek		= generic_file_llseek,
};
