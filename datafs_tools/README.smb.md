# datafs SMB sample

`datafs_smb.bpf.c` is a read-only SMB2.1 guest client. The mount argument is
`server/share`, where `server` is the SMB server name used in the UNC tree path
and `share` is an anonymously readable Samba share.

The sample starts a fresh SMB session for every datafs operation. It supports
lookup, stat, directory listing, and reads. It intentionally does not support
credentials, signing, encryption, DFS referrals, durable handles, writes, or
non-ASCII names. The TCP-devmem command is not implemented by this provider
because it does not loan sockets and requires a multi-request handshake.

A minimal Samba share is:

```ini
[global]
map to guest = Bad User
server min protocol = SMB2_10
server signing = disabled

[public]
path = /srv/datafs-public
guest ok = yes
read only = yes
browseable = yes
```

Build and mount it with:

```bash
make -C datafs_tools datafs_smb.bpf.o datafs_smb_loader
./datafs_tools/datafs_smb_loader &
modprobe datafs
mkdir -p /tmp/datafs
mount -t datafs none /tmp/datafs \
  -o servers=192.0.2.10:445,ops=datafs_smb,arg=SERVER/public,timeout_ms=5000,buf_size=4096,pool_size=8
```
