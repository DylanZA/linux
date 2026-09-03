// SPDX-License-Identifier: GPL-2.0
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <net/net_namespace.h>

#include "datafs.h"

MODULE_AUTHOR("Dylan Yudaken <dyudaken@gmail.com>");
MODULE_DESCRIPTION("Read-only netfslib filesystem over TCP and BPF");
MODULE_LICENSE("GPL");

static struct kmem_cache *datafs_inode_cachep;

enum datafs_param {
	datafs_opt_servers,
	datafs_opt_ops,
	datafs_opt_arg,
	datafs_opt_timeout_ms,
	datafs_opt_buf_size,
	datafs_opt_pool_size,
};

static const struct fs_parameter_spec datafs_fs_parameters[] = {
	fsparam_string("servers",	datafs_opt_servers),
	fsparam_string("ops",		datafs_opt_ops),
	fsparam_string("arg",		datafs_opt_arg),
	fsparam_u32("timeout_ms",	datafs_opt_timeout_ms),
	fsparam_u32("buf_size",	datafs_opt_buf_size),
	fsparam_u32("pool_size",	datafs_opt_pool_size),
	{}
};

/**
 * datafs_free_opts() - Release mount option strings.
 * @opts: option set owned by a mount context or live superblock.
 *
 * Frees the three heap-allocated string options. Callers must not use @opts
 * after this returns.
 */
static void datafs_free_opts(struct datafs_mount_opts *opts)
{
	kfree(opts->servers);
	kfree(opts->ops_name);
	kfree(opts->arg);
}

/**
 * datafs_replace_string() - Replace a parsed string option without leaking.
 * @slot: pointer slot owning the current value
 * @value: replacement string to duplicate
 *
 * Duplicates @value, frees the prior value, and stores the new pointer in
 * @slot. This keeps re-parsing safe against a partial mount failure.
 *
 * Return: 0, or -ENOMEM.
 */
static int datafs_replace_string(char **slot, const char *value)
{
	char *str;

	str = kstrdup(value, GFP_KERNEL);
	if (!str)
		return -ENOMEM;
	kfree(*slot);
	*slot = str;
	return 0;
}

/**
 * datafs_parse_param() - Parse one datafs mount option into the superblock.
 * @fc: filesystem context owning the pending superblock
 * @param: one mount option with its value
 *
 * Validates and stores the option into fc->s_fs_info. Numeric and string
 * options are bounded to their protocol maxima.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_parse_param(struct fs_context *fc,
			      struct fs_parameter *param)
{
	struct datafs_sb_info *sbi = fc->s_fs_info;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, datafs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case datafs_opt_servers:
		return datafs_replace_string(&sbi->opts.servers, param->string);
	case datafs_opt_ops:
		if (!param->string[0])
			return -EINVAL;
		if (strnlen(param->string, TCPFS_NAME_LEN) == TCPFS_NAME_LEN)
			return -ENAMETOOLONG;
		return datafs_replace_string(&sbi->opts.ops_name, param->string);
	case datafs_opt_arg:
		if (strnlen(param->string, TCPFS_MOUNT_ARG_MAX) ==
		    TCPFS_MOUNT_ARG_MAX)
			return -ENAMETOOLONG;
		return datafs_replace_string(&sbi->opts.arg, param->string);
	case datafs_opt_timeout_ms:
		if (!result.uint_32)
			return -EINVAL;
		sbi->opts.timeout_ms = result.uint_32;
		return 0;
	case datafs_opt_buf_size:
		if (!result.uint_32 || result.uint_32 > TCPFS_PAYLOAD_MAX)
			return -EINVAL;
		sbi->opts.buf_size = result.uint_32;
		return 0;
	case datafs_opt_pool_size:
		if (!result.uint_32 ||
		    result.uint_32 > DATAFS_MAX_CONNECTIONS)
			return -EINVAL;
		sbi->opts.pool_size = result.uint_32;
		return 0;
	default:
		return -EINVAL;
	}
}

/**
 * datafs_parse_one_server() - Parse one host:port endpoint.
 * @server: endpoint storage to populate
 * @token: ![...]:port or dotted-quad:port string
 *
 * Accepts numeric IPv4 or bracketed IPv6 endpoints only; DNS names are not
 * supported.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_parse_one_server(struct datafs_server *server, char *token)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&server->addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&server->addr;
	char *host;
	char *portp;
	const char *endp;
	unsigned long port;

	if (!token || !*token)
		return -EINVAL;

	memset(server, 0, sizeof(*server));
	if (token[0] == '[') {
		host = token + 1;
		portp = strchr(host, ']');
		if (!portp || portp[1] != ':')
			return -EINVAL;
		*portp = '\0';
		portp += 2;
		if (!in6_pton(host, -1, (u8 *)&sin6->sin6_addr, -1, NULL))
			return -EINVAL;
		if (kstrtoul(portp, 10, &port) || !port || port > 65535)
			return -EINVAL;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		server->addrlen = sizeof(*sin6);
		return 0;
	}

	portp = strrchr(token, ':');
	if (!portp)
		return -EINVAL;
	*portp++ = '\0';
	if (kstrtoul(portp, 10, &port) || !port || port > 65535)
		return -EINVAL;
	if (!in4_pton(token, -1, (u8 *)&sin->sin_addr.s_addr, -1, &endp) ||
	    (endp && *endp))
		return -EINVAL;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	server->addrlen = sizeof(*sin);
	return 0;
}

/**
 * datafs_parse_servers() - Build the endpoint list from the servers option.
 * @sbi: superblock whose endpoint list is materialized
 *
 * Splits the comma-separated servers option into the bounded server array.
 * At least one valid endpoint is required.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_parse_servers(struct datafs_sb_info *sbi)
{
	struct datafs_server *server;
	char *servers;
	char *token;
	char *p;
	int ret = 0;

	if (!sbi->opts.servers)
		return -EINVAL;

	servers = kstrdup(sbi->opts.servers, GFP_KERNEL);
	if (!servers)
		return -ENOMEM;

	p = servers;
	while ((token = strsep(&p, ",")) != NULL) {
		if (sbi->nr_servers == DATAFS_MAX_SERVERS) {
			ret = -E2BIG;
			break;
		}
		server = &sbi->servers[sbi->nr_servers];
		ret = datafs_parse_one_server(server, token);
		if (ret)
			break;
		sbi->nr_servers++;
	}

	kfree(servers);
	return ret ?: (sbi->nr_servers ? 0 : -EINVAL);
}

/**
 * datafs_show_options() - Report effective options through /proc/mounts.
 * @m: seq_file to write
 * @root: mount root dentry
 *
 * Return: 0.
 */
static int datafs_show_options(struct seq_file *m, struct dentry *root)
{
	struct datafs_sb_info *sbi = DATAFS_SB(root->d_sb);

	if (sbi->opts.servers)
		seq_show_option(m, "servers", sbi->opts.servers);
	if (sbi->opts.ops_name)
		seq_show_option(m, "ops", sbi->opts.ops_name);
	if (sbi->opts.arg)
		seq_show_option(m, "arg", sbi->opts.arg);
	seq_printf(m, ",timeout_ms=%u,buf_size=%u,pool_size=%u",
		   sbi->opts.timeout_ms, sbi->opts.buf_size,
		   sbi->opts.pool_size);
	return 0;
}

static const struct super_operations datafs_sops = {
	.alloc_inode	= datafs_alloc_inode,
	.free_inode	= datafs_free_inode,
	.statfs		= simple_statfs,
	.drop_inode	= inode_just_drop,
	.show_options	= datafs_show_options,
};

/**
 * datafs_fill_super() - Populate a new datafs superblock at mount time.
 * @sb: superblock to fill
 * @fc: filesystem context holding the parsed mount options
 *
 * Binds the protocol provider, initializes the transport pool, and creates
 * the mount root inode. On success the context releases ownership of the
 * superblock state.
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct datafs_sb_info *sbi = sb->s_fs_info;
	struct inode *inode;
	int ret;

	if (!sbi || !sbi->opts.ops_name)
		return -EINVAL;

	ret = datafs_parse_servers(sbi);
	if (ret)
		return ret;

	sbi->bpf = tcpfs_bpf_get_wait(sbi->opts.ops_name,
				      msecs_to_jiffies(sbi->opts.timeout_ms));
	if (IS_ERR(sbi->bpf)) {
		ret = PTR_ERR(sbi->bpf);
		sbi->bpf = NULL;
		return ret;
	}
	if (!sbi->bpf)
		return -ENOENT;
	sbi->ops = tcpfs_bpf_ops(sbi->bpf);
	if (!sbi->ops) {
		ret = -ENOENT;
		goto out_put_bpf;
	}
	ret = datafs_conn_pool_init(sbi);
	if (ret)
		goto out_put_bpf;

	sb->s_magic = DATAFS_MAGIC;
	sb->s_op = &datafs_sops;
	sb->s_flags |= SB_RDONLY;
	sb->s_time_gran = 1;
	sb->s_maxbytes = MAX_LFS_FILESIZE;

	inode = datafs_get_inode(sb, NULL, S_IFDIR | 0555, "", 1, 0);
	if (!inode) {
		ret = -ENOMEM;
		goto out_destroy_pool;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto out_destroy_pool;
	}

	fc->s_fs_info = NULL;
	return 0;

out_destroy_pool:
	datafs_conn_pool_destroy(sbi);
out_put_bpf:
	tcpfs_bpf_put(sbi->bpf);
	sbi->bpf = NULL;
	sbi->ops = NULL;
	return ret;
}

/**
 * datafs_get_tree() - Create a device-independent datafs superblock.
 * @fc: filesystem context
 *
 * Return: 0 on success, or a negative errno.
 */
static int datafs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, datafs_fill_super);
}

/**
 * datafs_free_fc() - Release an abandoned filesystem context.
 * @fc: filesystem context whose pending state is freed
 *
 * Called when mount setup fails partway or the context is discarded. Releases
 * the superblock state, the network namespace reference, and option strings.
 */
static void datafs_free_fc(struct fs_context *fc)
{
	struct datafs_sb_info *sbi = fc->s_fs_info;

	if (!sbi)
		return;
	put_net(sbi->net_ns);
	datafs_free_opts(&sbi->opts);
	kfree(sbi);
}

static const struct fs_context_operations datafs_context_ops = {
	.free		= datafs_free_fc,
	.parse_param	= datafs_parse_param,
	.get_tree	= datafs_get_tree,
};

/**
 * datafs_init_fs_context() - Allocate and initialize per-mount state.
 * @fc: filesystem context receiving the new superblock state
 *
 * Allocates the superblock info, applies defaults, and captures the caller's
 * network namespace. On success fc->s_fs_info owns the allocation.
 *
 * Return: 0 on success, or -ENOMEM.
 */
static int datafs_init_fs_context(struct fs_context *fc)
{
	struct datafs_sb_info *sbi;

	sbi = kzalloc_obj(*sbi, GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->opts.timeout_ms = DATAFS_DEFAULT_TIMEOUT;
	sbi->opts.buf_size = DATAFS_DEFAULT_BUF_SIZE;
	sbi->opts.pool_size = DATAFS_DEFAULT_POOL_SIZE;
	sbi->net_ns = get_net(current->nsproxy->net_ns);
	atomic64_set(&sbi->next_id, 1);
	fc->s_fs_info = sbi;
	fc->ops = &datafs_context_ops;
	return 0;
}

/**
 * datafs_kill_sb() - Tear down a live datafs mount.
 * @sb: superblock being unmounted
 *
 * Destroys the transport pool, releases the provider and network namespace,
 * frees option strings, and releases the superblock state.
 */
static void datafs_kill_sb(struct super_block *sb)
{
	struct datafs_sb_info *sbi = sb->s_fs_info;

	kill_anon_super(sb);
	if (!sbi)
		return;

	datafs_conn_pool_destroy(sbi);
	tcpfs_bpf_put(sbi->bpf);
	put_net(sbi->net_ns);
	datafs_free_opts(&sbi->opts);
	kfree(sbi);
}

static struct file_system_type datafs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "datafs",
	.init_fs_context	= datafs_init_fs_context,
	.parameters		= datafs_fs_parameters,
	.kill_sb		= datafs_kill_sb,
};

/**
 * datafs_init_once() - Initialize the embedded netfs inode in a slab object.
 * @foo: slab object (a datafs_inode_info)
 */
static void datafs_init_once(void *foo)
{
	struct datafs_inode_info *di = foo;

	inode_init_once(&di->netfs.inode);
}

/**
 * datafs_alloc_inode() - Allocate a datafs inode from the slab cache.
 * @sb: owning superblock
 *
 * Return: the allocated inode, or NULL on allocation failure.
 */
struct inode *datafs_alloc_inode(struct super_block *sb)
{
	struct datafs_inode_info *di;

	di = alloc_inode_sb(sb, datafs_inode_cachep, GFP_KERNEL);
	if (!di)
		return NULL;
	di->remote_ino = 0;
	di->path = NULL;
	return &di->netfs.inode;
}

/**
 * datafs_free_inode() - Release a datafs inode and return it to the slab cache.
 * @inode: inode to release
 *
 * Frees the inode's path string before returning the object to its cache.
 */
void datafs_free_inode(struct inode *inode)
{
	struct datafs_inode_info *di = DATAFS_I(inode);

	kfree(di->path);
	kmem_cache_free(datafs_inode_cachep, di);
}

/**
 * datafs_init() - Register the BPF interface and the datafs filesystem.
 *
 * Return: 0 on success, or a negative errno.
 */
static int __init datafs_init(void)
{
	int ret;

	datafs_inode_cachep =
		kmem_cache_create("datafs_inode_cache",
				  sizeof(struct datafs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, datafs_init_once);
	if (!datafs_inode_cachep)
		return -ENOMEM;

	ret = tcpfs_bpf_init();
	if (ret)
		goto out_cache;

	ret = register_filesystem(&datafs_fs_type);
	if (ret)
		goto out_bpf;
	return 0;

out_bpf:
	tcpfs_bpf_exit();
out_cache:
	kmem_cache_destroy(datafs_inode_cachep);
	return ret;
}

/**
 * datafs_exit() - Unregister datafs after all mounted instances are gone.
 */
static void __exit datafs_exit(void)
{
	unregister_filesystem(&datafs_fs_type);
	tcpfs_bpf_exit();
	rcu_barrier();
	kmem_cache_destroy(datafs_inode_cachep);
}

module_init(datafs_init);
module_exit(datafs_exit);

MODULE_ALIAS_FS("datafs");
