/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_DATAFS_DATAFS_H
#define _FS_DATAFS_DATAFS_H

#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/list.h>
#include <linux/netfs.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/datafs.h>
#include <linux/xarray.h>

#define DATAFS_MAGIC		0x64617461
#define DATAFS_DEFAULT_TIMEOUT	5000
#define DATAFS_DEFAULT_BUF_SIZE	TCPFS_PAYLOAD_MAX
#define DATAFS_DEFAULT_POOL_SIZE	8
#define DATAFS_MAX_SERVERS	8
#define DATAFS_MAX_CONNECTIONS	64

struct datafs_conn_pool;
struct datafs_async_transport;
struct datafs_devmem_loan;
struct datafs_devmem_read;
struct io_uring_cmd;

struct net;

struct tcpfs_bpf_ops {
	struct list_head list;
	struct tcpfs_ops *ops;
	refcount_t refs;
	bool dead;
};

struct datafs_server {
	struct sockaddr_storage addr;
	int addrlen;
};

struct datafs_mount_opts {
	char *servers;
	char *ops_name;
	char *arg;
	u32 timeout_ms;
	u32 buf_size;
	u32 pool_size;
};

struct datafs_sb_info {
	struct datafs_mount_opts opts;
	struct datafs_server servers[DATAFS_MAX_SERVERS];
	unsigned int nr_servers;
	struct tcpfs_bpf_ops *bpf;
	const struct tcpfs_ops *ops;
	struct net *net_ns;
	struct datafs_conn_pool *conn_pool;
	struct datafs_async_transport *async_transport;
	/* Protects the phase-2 loan registry and waiter list. */
	spinlock_t loan_lock;
	struct list_head loan_waiters;
	struct xarray devmem_loans;
	u32 next_loan_id;
	struct xarray devmem_copies;
	u32 next_copy_id;
	atomic64_t next_id;
};

struct datafs_inode_info {
	struct netfs_inode netfs;
	u64 remote_ino;
	char *path;
};

static inline struct datafs_inode_info *DATAFS_I(struct inode *inode)
{
	return container_of(inode, struct datafs_inode_info, netfs.inode);
}

static inline struct datafs_sb_info *DATAFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

int datafs_call(struct datafs_sb_info *sbi, struct tcpfs_ctx *ctx);
int datafs_bpf_build_request(
	int (*callback)(struct tcpfs_build_request_ctx *ctx),
	struct tcpfs_ctx *ctx);
int datafs_bpf_frame_tx(int (*callback)(struct tcpfs_frame_tx_ctx *ctx),
			       struct tcpfs_ctx *ctx);
int datafs_bpf_recv_response(
	int (*callback)(struct tcpfs_recv_response_ctx *ctx),
	struct tcpfs_ctx *ctx);
int datafs_bpf_unframe_rx(
	int (*callback)(const struct tcpfs_unframe_rx_ctx *ctx),
	const void *data, size_t len, size_t *frame_len);
int datafs_bpf_handle_response(
	int (*callback)(struct tcpfs_handle_response_ctx *ctx),
	struct tcpfs_ctx *ctx);
int datafs_bpf_loan_socket(
	int (*callback)(struct tcpfs_loan_socket_ctx *ctx),
	struct tcpfs_socket_loan *loan);
void datafs_bpf_return_socket(
	void (*callback)(struct tcpfs_return_socket_ctx *ctx),
	struct tcpfs_socket_loan *loan);
int datafs_conn_pool_init(struct datafs_sb_info *sbi);
void datafs_conn_pool_destroy(struct datafs_sb_info *sbi);
ssize_t datafs_read_to_iter(struct datafs_sb_info *sbi, const char *path,
			    u32 path_len, u64 ino, u64 offset, size_t len,
			    struct iov_iter *to);
int datafs_read_async(struct datafs_sb_info *sbi, const char *path,
			      u32 path_len, u64 ino, u64 offset, size_t len,
			      struct netfs_io_subrequest *subreq);
int datafs_devmem_read(struct datafs_sb_info *sbi, const char *path,
		       u32 path_len, u64 ino, u64 offset, size_t len,
		       u16 host_group, u32 dmabuf_id, u32 flags,
		       struct io_uring_cmd *cmd, unsigned int issue_flags);
int datafs_devmem_cancel(struct io_uring_cmd *cmd);
int datafs_devmem_dontneed(struct datafs_sb_info *sbi, u16 loan_id,
			   u32 dmabuf_id, u32 token_start,
			   u32 token_count);
int datafs_devmem_copy_response(struct datafs_sb_info *sbi,
				struct io_uring_cmd *cmd,
				unsigned int issue_flags);
void datafs_devmem_shutdown(struct datafs_sb_info *sbi);

int tcpfs_bpf_init(void);
void tcpfs_bpf_exit(void);
struct tcpfs_bpf_ops *tcpfs_bpf_get(const char *name);
struct tcpfs_bpf_ops *tcpfs_bpf_get_wait(const char *name,
					 unsigned long timeout);
void tcpfs_bpf_put(struct tcpfs_bpf_ops *entry);
const struct tcpfs_ops *tcpfs_bpf_ops(const struct tcpfs_bpf_ops *entry);

struct inode *datafs_get_inode(struct super_block *sb, const struct inode *dir,
			       umode_t mode, const char *path, u64 ino,
			       u64 size);
struct inode *datafs_alloc_inode(struct super_block *sb);
void datafs_free_inode(struct inode *inode);

extern const struct inode_operations datafs_dir_iops;
extern const struct file_operations datafs_dir_fops;
extern const struct inode_operations datafs_file_iops;
extern const struct file_operations datafs_file_fops;
extern const struct address_space_operations datafs_aops;
extern const struct netfs_request_ops datafs_netfs_ops;

#endif /* _FS_DATAFS_DATAFS_H */
