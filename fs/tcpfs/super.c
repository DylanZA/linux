// SPDX-License-Identifier: GPL-2.0
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include "tcpfs.h"

MODULE_AUTHOR("tcpfs contributors");
MODULE_DESCRIPTION("TCP-backed BPF callback filesystem");
MODULE_LICENSE("GPL");

static struct kmem_cache *tcpfs_inode_cachep;

enum tcpfs_param {
	Opt_servers,
	Opt_ops,
	Opt_bucket,
	Opt_timeout_ms,
	Opt_buf_size,
	Opt_buf_count,
};

static const struct fs_parameter_spec tcpfs_fs_parameters[] = {
	fsparam_string("servers",	Opt_servers),
	fsparam_string("ops",		Opt_ops),
	fsparam_string("bucket",	Opt_bucket),
	fsparam_u32("timeout_ms",	Opt_timeout_ms),
	fsparam_u32("buf_size",		Opt_buf_size),
	fsparam_u32("buf_count",	Opt_buf_count),
	{}
};

static void tcpfs_free_opts(struct tcpfs_mount_opts *opts)
{
	kfree(opts->servers);
	kfree(opts->ops_name);
	kfree(opts->bucket);
}

static int tcpfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct tcpfs_sb_info *sbi = fc->s_fs_info;
	struct fs_parse_result result;
	char *str;
	int opt;

	opt = fs_parse(fc, tcpfs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_servers:
		str = kstrdup(param->string, GFP_KERNEL);
		if (!str)
			return -ENOMEM;
		kfree(sbi->opts.servers);
		sbi->opts.servers = str;
		break;
	case Opt_ops:
		str = kstrdup(param->string, GFP_KERNEL);
		if (!str)
			return -ENOMEM;
		kfree(sbi->opts.ops_name);
		sbi->opts.ops_name = str;
		break;
	case Opt_bucket:
		str = kstrdup(param->string, GFP_KERNEL);
		if (!str)
			return -ENOMEM;
		kfree(sbi->opts.bucket);
		sbi->opts.bucket = str;
		break;
	case Opt_timeout_ms:
		sbi->opts.timeout_ms = result.uint_32;
		break;
	case Opt_buf_size:
		if (!result.uint_32 || result.uint_32 > TCPFS_PAYLOAD_MAX)
			return -EINVAL;
		sbi->opts.buf_size = result.uint_32;
		break;
	case Opt_buf_count:
		if (!result.uint_32)
			return -EINVAL;
		sbi->opts.buf_count = result.uint_32;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int tcpfs_parse_one_server(struct tcpfs_server *server, char *token)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&server->addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&server->addr;
	char *host, *portp;
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

static int tcpfs_parse_servers(struct tcpfs_sb_info *sbi)
{
	char *servers, *p, *token;
	int ret = 0;

	if (!sbi->opts.servers)
		return -EINVAL;

	servers = kstrdup(sbi->opts.servers, GFP_KERNEL);
	if (!servers)
		return -ENOMEM;

	p = servers;
	while ((token = strsep(&p, ",")) != NULL) {
		if (sbi->nr_servers == TCPFS_MAX_SERVERS) {
			ret = -E2BIG;
			break;
		}
		ret = tcpfs_parse_one_server(&sbi->servers[sbi->nr_servers],
					     token);
		if (ret)
			break;
		sbi->nr_servers++;
	}

	kfree(servers);
	return ret ?: (sbi->nr_servers ? 0 : -EINVAL);
}

static int tcpfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct tcpfs_sb_info *sbi = TCPFS_SB(root->d_sb);

	if (sbi->opts.servers)
		seq_show_option(m, "servers", sbi->opts.servers);
	if (sbi->opts.ops_name)
		seq_show_option(m, "ops", sbi->opts.ops_name);
	if (sbi->opts.bucket)
		seq_show_option(m, "bucket", sbi->opts.bucket);
	seq_printf(m, ",timeout_ms=%u,buf_size=%u,buf_count=%u",
		   sbi->opts.timeout_ms, sbi->opts.buf_size,
		   sbi->opts.buf_count);
	return 0;
}

static const struct super_operations tcpfs_sops = {
	.alloc_inode	= tcpfs_alloc_inode,
	.free_inode	= tcpfs_free_inode,
	.statfs		= simple_statfs,
	.drop_inode	= inode_just_drop,
	.show_options	= tcpfs_show_options,
};

static int tcpfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct tcpfs_sb_info *sbi = sb->s_fs_info;
	struct inode *inode;
	int ret;

	if (!sbi)
		return -EINVAL;

	if (!sbi->opts.ops_name)
		return -EINVAL;

	ret = tcpfs_parse_servers(sbi);
	if (ret)
		return ret;

	pr_info("tcpfs: mount begin ops=%s servers=%u bucket=%s timeout_ms=%u buf_size=%u buf_count=%u\n",
		sbi->opts.ops_name, sbi->nr_servers, sbi->opts.bucket ?: "",
		sbi->opts.timeout_ms, sbi->opts.buf_size, sbi->opts.buf_count);

	sbi->bpf_ops = tcpfs_bpf_get_wait(sbi->opts.ops_name,
					  msecs_to_jiffies(sbi->opts.timeout_ms));
	if (IS_ERR(sbi->bpf_ops)) {
		ret = PTR_ERR(sbi->bpf_ops);
		sbi->bpf_ops = NULL;
		pr_warn("tcpfs: mount failed waiting for ops=%s err=%d\n",
			sbi->opts.ops_name, ret);
		return ret;
	}
	if (!sbi->bpf_ops) {
		pr_warn("tcpfs: mount timed out waiting for ops=%s\n",
			sbi->opts.ops_name);
		return -ENOENT;
	}

	ret = tcpfs_pool_create(sbi);
	if (ret) {
		pr_warn("tcpfs: mount failed creating pool err=%d\n", ret);
		tcpfs_bpf_put(sbi->bpf_ops);
		sbi->bpf_ops = NULL;
		return ret;
	}

	sb->s_fs_info = sbi;
	sb->s_magic = TCPFS_MAGIC;
	sb->s_op = &tcpfs_sops;
	sb->s_time_gran = 1;
	sb->s_maxbytes = MAX_LFS_FILESIZE;

	inode = tcpfs_get_inode(sb, NULL, S_IFDIR | 0555, "", 1, 0);
	if (!inode) {
		tcpfs_pool_destroy(sbi);
		tcpfs_bpf_put(sbi->bpf_ops);
		sbi->bpf_ops = NULL;
		return -ENOMEM;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		tcpfs_pool_destroy(sbi);
		tcpfs_bpf_put(sbi->bpf_ops);
		sbi->bpf_ops = NULL;
		return -ENOMEM;
	}

	pr_info("tcpfs: mount ready ops=%s bucket=%s\n",
		sbi->opts.ops_name, sbi->opts.bucket ?: "");

	fc->s_fs_info = NULL;
	return 0;
}

static int tcpfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, tcpfs_fill_super);
}

static void tcpfs_free_fc(struct fs_context *fc)
{
	struct tcpfs_sb_info *sbi = fc->s_fs_info;

	if (!sbi)
		return;
	tcpfs_free_opts(&sbi->opts);
	kfree(sbi);
}

static const struct fs_context_operations tcpfs_context_ops = {
	.free		= tcpfs_free_fc,
	.parse_param	= tcpfs_parse_param,
	.get_tree	= tcpfs_get_tree,
};

static int tcpfs_init_fs_context(struct fs_context *fc)
{
	struct tcpfs_sb_info *sbi;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->opts.timeout_ms = TCPFS_DEFAULT_TIMEOUT;
	sbi->opts.buf_size = TCPFS_DEFAULT_BUF_SIZE;
	sbi->opts.buf_count = TCPFS_DEFAULT_BUF_COUNT;
	atomic64_set(&sbi->next_id, 1);
	fc->s_fs_info = sbi;
	fc->ops = &tcpfs_context_ops;
	return 0;
}

static void tcpfs_kill_sb(struct super_block *sb)
{
	struct tcpfs_sb_info *sbi = sb->s_fs_info;

	kill_anon_super(sb);
	if (sbi) {
		pr_info("tcpfs: unmount ops=%s bucket=%s\n",
			sbi->opts.ops_name ?: "", sbi->opts.bucket ?: "");
		tcpfs_pool_destroy(sbi);
		tcpfs_bpf_put(sbi->bpf_ops);
		tcpfs_free_opts(&sbi->opts);
		kfree(sbi);
	}
}

static struct file_system_type tcpfs_fs_type = {
	.name			= "tcpfs",
	.init_fs_context	= tcpfs_init_fs_context,
	.parameters		= tcpfs_fs_parameters,
	.kill_sb		= tcpfs_kill_sb,
	.fs_flags		= FS_USERNS_MOUNT,
};

static void tcpfs_init_once(void *foo)
{
	struct tcpfs_inode_info *ti = foo;

	inode_init_once(&ti->vfs_inode);
}

static int __init tcpfs_init(void)
{
	int ret;

	tcpfs_inode_cachep = kmem_cache_create("tcpfs_inode_cache",
					       sizeof(struct tcpfs_inode_info),
					       0, SLAB_RECLAIM_ACCOUNT,
					       tcpfs_init_once);
	if (!tcpfs_inode_cachep)
		return -ENOMEM;

	ret = tcpfs_bpf_init();
	if (ret)
		goto out_cache;

	ret = register_filesystem(&tcpfs_fs_type);
	if (ret)
		goto out_bpf;
	pr_info("tcpfs: module loaded\n");
	return 0;

out_bpf:
	tcpfs_bpf_exit();
out_cache:
	kmem_cache_destroy(tcpfs_inode_cachep);
	return ret;
}

static void __exit tcpfs_exit(void)
{
	unregister_filesystem(&tcpfs_fs_type);
	tcpfs_bpf_exit();
	kmem_cache_destroy(tcpfs_inode_cachep);
	pr_info("tcpfs: module unloaded\n");
}

struct inode *tcpfs_alloc_inode(struct super_block *sb)
{
	struct tcpfs_inode_info *ti;

	ti = alloc_inode_sb(sb, tcpfs_inode_cachep, GFP_KERNEL);
	if (!ti)
		return NULL;
	ti->remote_ino = 0;
	ti->path = NULL;
	return &ti->vfs_inode;
}

void tcpfs_free_inode(struct inode *inode)
{
	struct tcpfs_inode_info *ti = TCPFS_I(inode);

	kfree(ti->path);
	kmem_cache_free(tcpfs_inode_cachep, ti);
}

module_init(tcpfs_init);
module_exit(tcpfs_exit);
