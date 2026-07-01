/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_TCPFS_TCPFS_H
#define _FS_TCPFS_TCPFS_H

#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/tcpfs.h>
#include <linux/workqueue.h>

#define TCPFS_MAGIC		0x74637066
#define TCPFS_DEFAULT_TIMEOUT	5000
#define TCPFS_DEFAULT_BUF_SIZE	TCPFS_PAYLOAD_MAX
#define TCPFS_DEFAULT_BUF_COUNT	8
#define TCPFS_MAX_SERVERS	8

struct tcpfs_bpf_ops {
	struct list_head list;
	struct tcpfs_ops *ops;
	refcount_t refs;
	bool dead;
};

struct io_uring_cmd;

struct tcpfs_server {
	struct sockaddr_storage addr;
	int addrlen;
};

struct tcpfs_mount_opts {
	char *servers;
	char *ops_name;
	char *arg;
	u32 timeout_ms;
	u32 buf_size;
	u32 buf_count;
};

struct tcpfs_sb_info {
	struct tcpfs_mount_opts opts;
	struct tcpfs_server servers[TCPFS_MAX_SERVERS];
	unsigned int nr_servers;
	struct tcpfs_bpf_ops *bpf_ops;
	struct tcpfs_conn_pool *pool;
	atomic64_t next_id;
};

struct tcpfs_inode_info {
	struct inode vfs_inode;
	u64 remote_ino;
	char *path;
};

static inline struct tcpfs_inode_info *TCPFS_I(struct inode *inode)
{
	return container_of(inode, struct tcpfs_inode_info, vfs_inode);
}

static inline struct tcpfs_sb_info *TCPFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

struct tcpfs_bpf_ops *tcpfs_bpf_get(const char *name);
struct tcpfs_bpf_ops *tcpfs_bpf_get_wait(const char *name,
					 unsigned long timeout);
void tcpfs_bpf_put(struct tcpfs_bpf_ops *ops);
int tcpfs_bpf_init(void);
void tcpfs_bpf_exit(void);

int tcpfs_call(struct tcpfs_sb_info *sbi, struct tcpfs_ctx *ctx);
ssize_t tcpfs_read_to_iter(struct tcpfs_sb_info *sbi, const char *path,
			   u32 path_len, u64 ino, u64 offset, size_t len,
			   struct iov_iter *to);
int tcpfs_read_zc_async(struct tcpfs_sb_info *sbi, const char *path,
			u32 path_len, u64 ino, u64 offset, size_t len,
			u32 ifq_idx, struct io_uring_cmd *cmd,
			unsigned int issue_flags);
int tcpfs_cancel_zc_async(struct io_uring_cmd *cmd);
int tcpfs_pool_create(struct tcpfs_sb_info *sbi);
void tcpfs_pool_destroy(struct tcpfs_sb_info *sbi);
struct inode *tcpfs_get_inode(struct super_block *sb, const struct inode *dir,
			      umode_t mode, const char *path, u64 ino,
			      u64 size);
struct inode *tcpfs_alloc_inode(struct super_block *sb);
void tcpfs_free_inode(struct inode *inode);

extern const struct inode_operations tcpfs_dir_iops;
extern const struct file_operations tcpfs_dir_fops;
extern const struct inode_operations tcpfs_file_iops;
extern const struct file_operations tcpfs_file_fops;

#endif /* _FS_TCPFS_TCPFS_H */
