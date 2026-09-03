// SPDX-License-Identifier: GPL-2.0
#include <linux/limits.h>
#include <linux/io_uring/cmd.h>
#include <linux/slab.h>
#include <uapi/linux/datafs.h>

#include "datafs.h"

#define DATAFS_DIR_EOF	LLONG_MAX

struct datafs_dirent {
	const char *name;
	size_t len;
	unsigned int type;
};

/**
 * datafs_open() - Prepare a regular file for read-only netfs access.
 * @inode: inode being opened
 * @file: file being opened
 *
 * Rejects write access and marks the file O_DIRECT-capable.
 *
 * Return: 0 on success, or -EROFS.
 */
static int datafs_open(struct inode *inode, struct file *file)
{
	if (file->f_mode & FMODE_WRITE)
		return -EROFS;
	file->f_mode |= FMODE_CAN_ODIRECT | FMODE_NOWAIT;
	return 0;
}

/**
 * datafs_uring_cmd() - Dispatch datafs TCP-devmem io_uring commands.
 * @cmd: uring command
 * @issue_flags: command issue flags (CANCEL, COMPLETE_DEFER, ..., CQE32)
 *
 * Validates SQE fields and routes to read or DONTNEED handling. Reads require
 * O_DIRECT; DONTNEED returns published token ranges.
 *
 * Return: -EIOCBQUEUED for an accepted read, or a negative errno.
 */
static int datafs_uring_cmd(struct io_uring_cmd *cmd,
			    unsigned int issue_flags)
{
	const struct io_uring_sqe *sqe = cmd->sqe;
	const struct datafs_uring_devmem_cmd *dcmd;
	struct inode *inode = file_inode(cmd->file);
	struct datafs_inode_info *di = DATAFS_I(inode);
	struct datafs_sb_info *sbi = DATAFS_SB(inode->i_sb);
	u32 flags, dmabuf_id, len;
	u16 host_group;
	u64 offset;
	loff_t size;

	if (cmd->cmd_op == DATAFS_URING_CMD_COPY_RESPONSE) {
		const struct datafs_uring_copy_cmd *ccmd =
			io_uring_sqe_cmd(sqe, struct datafs_uring_copy_cmd);

		if (unlikely(issue_flags & IO_URING_F_CANCEL))
			return 0;
		if (!S_ISREG(inode->i_mode) || sqe->ioprio || sqe->__pad1 ||
		    !sqe->addr || !sqe->len ||
		    sqe->uring_cmd_flags != IORING_URING_CMD_FIXED ||
		    sqe->personality || sqe->zcrx_ifq_idx || ccmd->reserved)
			return -EINVAL;
		return datafs_devmem_copy_response(sbi, cmd, issue_flags);
	}
	if (cmd->cmd_op != DATAFS_URING_CMD_RECV_DEVMEM)
		return -EOPNOTSUPP;
	if (unlikely(issue_flags & IO_URING_F_CANCEL))
		return datafs_devmem_cancel(cmd);
	dcmd = io_uring_sqe_cmd(sqe, struct datafs_uring_devmem_cmd);
	/*
	 * datafs deliberately reuses the 32-bit SQE union slot exposed as
	 * zcrx_ifq_idx.  For this command it is a netdev RX dma-buf binding ID,
	 * not an interface-queue index.  Keep that private interpretation here
	 * instead of adding a datafs-specific alias to generic io_uring UAPI.
	 */
	flags = READ_ONCE(dcmd->flags);
	dmabuf_id = READ_ONCE(sqe->zcrx_ifq_idx);
	offset = READ_ONCE(dcmd->offset);
	len = READ_ONCE(sqe->len);
	host_group = READ_ONCE(sqe->buf_group);
	if (!S_ISREG(inode->i_mode) || !(cmd->file->f_flags & O_DIRECT))
		return -EINVAL;
	if (sqe->ioprio || sqe->__pad1 || sqe->addr ||
	    sqe->uring_cmd_flags || sqe->personality || dcmd->reserved)
		return -EINVAL;
	if (flags & ~(DATAFS_URING_F_WAIT_SOCKET |
		      DATAFS_URING_F_DEVMEM_DONTNEED))
		return -EINVAL;

	if (flags & DATAFS_URING_F_DEVMEM_DONTNEED) {
		if (flags & DATAFS_URING_F_WAIT_SOCKET || offset > U32_MAX ||
		    !len || len > 1024)
			return -EINVAL;
		return datafs_devmem_dontneed(sbi, host_group, dmabuf_id,
					      offset, len);
	}

	if (!dmabuf_id || !len || len > MAX_RW_COUNT)
		return -EINVAL;
	size = i_size_read(inode);
	if (size < 0 || offset > MAX_LFS_FILESIZE)
		return -EOVERFLOW;
	if (offset >= size)
		return 0;
	len = min_t(u64, len, size - offset);

	return datafs_devmem_read(sbi, di->path ?: "",
				 strlen(di->path ?: ""), di->remote_ino,
				 offset, len, host_group, dmabuf_id, flags,
				 cmd, issue_flags);
}

/**
 * datafs_init_request() - Attach filesystem context to a netfs read request.
 * @rreq: netfs read request
 * @file: file the request targets
 *
 * Return: 0.
 */
static int datafs_init_request(struct netfs_io_request *rreq,
			       struct file *file)
{
	rreq->io_streams[0].sreq_max_len = MAX_RW_COUNT;
	return 0;
}

/**
 * datafs_issue_read() - Execute one netfs subrequest.
 * @subreq: netfs subrequest to fulfill
 *
 * Uses the queued transport only for an explicitly asynchronous direct-I/O
 * request. Synchronous requests stay on the blocking exchange path and are
 * completed before this callback returns.
 */
static void datafs_issue_read(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct datafs_inode_info *di = DATAFS_I(rreq->inode);
	struct datafs_sb_info *sbi = DATAFS_SB(rreq->inode->i_sb);
	size_t remaining = subreq->len - subreq->transferred;
	size_t before;
	size_t copied;
	ssize_t ret;

	if (rreq->iocb && !is_sync_kiocb(rreq->iocb)) {
		ret = datafs_read_async(sbi, di->path, strlen(di->path),
					 di->remote_ino,
					 subreq->start + subreq->transferred,
					 remaining, subreq);
		if (!ret)
			return;
		subreq->error = ret;
		netfs_read_subreq_terminated(subreq);
		return;
	}

	before = iov_iter_count(&subreq->io_iter);
	ret = datafs_read_to_iter(sbi, di->path, strlen(di->path),
				  di->remote_ino,
				  subreq->start + subreq->transferred,
				  remaining, &subreq->io_iter);
	copied = before - iov_iter_count(&subreq->io_iter);
	if (copied) {
		subreq->transferred += copied;
		__set_bit(NETFS_SREQ_MADE_PROGRESS, &subreq->flags);
	}
	if (ret >= 0 && ret != copied)
		ret = -EIO;
	subreq->error = ret < 0 ? ret : 0;
	if (rreq->origin != NETFS_UNBUFFERED_READ &&
	    rreq->origin != NETFS_DIO_READ)
		__set_bit(NETFS_SREQ_CLEAR_TAIL, &subreq->flags);
	if (subreq->start + subreq->transferred >= rreq->i_size)
		__set_bit(NETFS_SREQ_HIT_EOF, &subreq->flags);
	netfs_read_subreq_terminated(subreq);
}

/**
 * datafs_prepare_read() - Reject a remote read requested with IOCB_NOWAIT.
 * @subreq: netfs subrequest to validate
 *
 * datafs cannot satisfy IOCB_NOWAIT from its remote transport.  Returning
 * -EAGAIN here lets the generic netfs direct-read path preserve the NOWAIT
 * contract instead of queueing an operation that is guaranteed to sleep.
 *
 * Return: 0 when the subrequest may be queued, or -EAGAIN for NOWAIT I/O.
 */
static int datafs_prepare_read(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *rreq = subreq->rreq;

	if (rreq->iocb && (rreq->iocb->ki_flags & IOCB_NOWAIT))
		return -EAGAIN;
	return 0;
}

const struct netfs_request_ops datafs_netfs_ops = {
	.init_request	= datafs_init_request,
	.prepare_read	= datafs_prepare_read,
	.issue_read	= datafs_issue_read,
};

const struct address_space_operations datafs_aops = {
	.read_folio	= netfs_read_folio,
	.readahead	= netfs_readahead,
	.release_folio	= netfs_release_folio,
	.invalidate_folio = netfs_invalidate_folio,
	.direct_IO	= noop_direct_IO,
	.migrate_folio	= filemap_migrate_folio,
};

/**
 * datafs_next_dirent() - Decode one length-prefixed directory record.
 * @pos: input position (advanced past the record)
 * @left: bytes remaining in @pos (consumed)
 * @dirent: decoded name and type
 *
 * Validates the record: a non-empty, unescaped name without path separators,
 * rejecting "." and "..".
 *
 * Return: 1 on a record, 0 at end of input, or -EIO on a malformed record.
 */
static int datafs_next_dirent(const char **pos, size_t *left,
			      struct datafs_dirent *dirent)
{
	const char *name = *pos;
	const char *nl;
	size_t consumed;
	size_t len;

	if (!*left)
		return 0;

	nl = memchr(name, '\n', *left);
	len = nl ? (size_t)(nl - name) : *left;
	consumed = len + !!nl;
	if (!len || memchr(name, '\0', len))
		return -EIO;

	dirent->type = DT_REG;
	if (name[len - 1] == '/') {
		dirent->type = DT_DIR;
		len--;
	}
	if (!len || len > NAME_MAX || memchr(name, '/', len) ||
	    (len == 1 && name[0] == '.') ||
	    (len == 2 && name[0] == '.' && name[1] == '.'))
		return -EIO;

	dirent->name = name;
	dirent->len = len;
	*pos += consumed;
	*left -= consumed;
	return 1;
}

/**
 * datafs_emit_dirents() - Emit validated provider directory records.
 * @ctx: directory context to emit into
 * @res: provider result containing the listing payload
 *
 * Validates every record first, then emits them, honoring ctx->pos.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_emit_dirents(struct dir_context *ctx,
			       const struct tcpfs_result *res)
{
	struct datafs_dirent dirent;
	const char *pos;
	size_t left;
	loff_t skip = ctx->pos - 2;
	int ret;

	if (res->payload_len > sizeof(res->payload))
		return -EIO;

	pos = res->payload;
	left = res->payload_len;
	while ((ret = datafs_next_dirent(&pos, &left, &dirent)) > 0)
		;
	if (ret)
		return ret;

	pos = res->payload;
	left = res->payload_len;
	while ((ret = datafs_next_dirent(&pos, &left, &dirent)) > 0) {
		if (skip) {
			skip--;
			continue;
		}
		if (!dir_emit(ctx, dirent.name, dirent.len, get_next_ino(),
			      dirent.type))
			return 0;
		ctx->pos++;
	}
	ctx->pos = DATAFS_DIR_EOF;
	return 0;
}

/**
 * datafs_iterate_shared() - Emit one directory listing at ctx->pos.
 * @file: directory file
 * @ctx: directory context
 *
 * Emits the synthetic dots before provider entries and tracks ctx->pos across
 * the provided listing.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_iterate_shared(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct datafs_inode_info *di = DATAFS_I(inode);
	struct datafs_sb_info *sbi = DATAFS_SB(inode->i_sb);
	struct tcpfs_ctx *tctx;
	int ret;

	if (ctx->pos < 0)
		return -EINVAL;
	if (ctx->pos < 2 && !dir_emit_dots(file, ctx))
		return 0;
	if (ctx->pos == DATAFS_DIR_EOF)
		return 0;

	tctx = kzalloc_obj(*tctx, GFP_KERNEL);
	if (!tctx)
		return -ENOMEM;

	tctx->op = TCPFS_OP_READDIR;
	tctx->ino = di->remote_ino;
	tctx->id = atomic64_inc_return(&sbi->next_id);
	strscpy(tctx->path, di->path ?: "", sizeof(tctx->path));
	tctx->path_len = strlen(tctx->path);

	ret = datafs_call(sbi, tctx);
	if (!ret)
		ret = tctx->result.error;
	if (!ret && tctx->result.type != TCPFS_RESULT_DIRENT)
		ret = -EIO;
	if (!ret)
		ret = datafs_emit_dirents(ctx, &tctx->result);

	kfree(tctx);
	return ret;
}

const struct file_operations datafs_file_fops = {
	.open		= datafs_open,
	.read_iter	= netfs_file_read_iter,
	.uring_cmd	= datafs_uring_cmd,
	.splice_read	= filemap_splice_read,
	.mmap_prepare	= generic_file_readonly_mmap_prepare,
	.llseek		= generic_file_llseek,
};

const struct file_operations datafs_dir_fops = {
	.iterate_shared	= datafs_iterate_shared,
	.llseek		= generic_file_llseek,
};
