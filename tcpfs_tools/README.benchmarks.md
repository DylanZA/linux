# tcpfs Benchmarks

Build:

```sh
make -C tcpfs_tools/
```

Run a direct tcpfs `uring_cmd` read benchmark against an already mounted tcpfs:

```sh
tcpfs_tools/tcpfs_bench_read -p /tmp/tcpfs/links.txt -m uring -l 2127 -i 1000 -w 20 -c
```

Pass `-I IFACE -q RXQ` to select NIC ZCRX. Omitting `-I` deliberately uses
the NODEV copy backend.

Run tcpfs `pread` with `O_DIRECT`:

```sh
tcpfs_tools/tcpfs_bench_read -p /tmp/tcpfs/links.txt -m pread -d -l 2127 -i 1000 -w 20 -c
```

Compare tcpfs against an already mounted S3 FUSE implementation:

```sh
FUSE_MNT=/tmp/s3fs tcpfs_tools/tcpfs_bench_compare_s3.sh --file links.txt --len 2127 --iters 1000 --warmup 20 --csv
```

The comparison script accepts any S3 FUSE mount, such as `s3fs`, `goofys`, or
`rclone mount`. If `FUSE_MOUNT_CMD` is set, the script runs it before the
benchmark. Example shape for `s3fs` against MinIO:

```sh
FUSE_MOUNT_CMD='s3fs publicbucket /tmp/s3fs -o url=http://192.168.1.238:9000 -o use_path_request_style -o passwd_file=/root/.passwd-s3fs' \
FUSE_MNT=/tmp/s3fs \
tcpfs_tools/tcpfs_bench_compare_s3.sh --file links.txt --len 2127 --iters 1000 --csv
```

Inside the virtme test VM, a tcpfs mount can be prepared with:

```sh
IFNAME=eth0 MTU=8000 SERVER=192.168.1.238:9000 ARG=publicbucket \
  tcpfs_tools/tcpfs_bench_mount_tcpfs.sh
tcpfs_tools/tcpfs_bench_compare_s3.sh --file out.data --len 1073741824 \
  --iters 1 --warmup 0 --zcrx-if eth0 --mtu 8000 --csv
```

The mount helper sets the guest interface MTU and verifies the complete path
with a don't-fragment ping before enabling NIC ZCRX. When MinIO runs on the VM
host, traffic terminates on the bridge's local port and does not traverse a
physical bridge member. In that case, leave the physical interface at 1500
and configure only the host bridge:

```sh
sudo ip link set dev br0 mtu 8000
```

MinIO must listen on an address reachable from the guest; the guest's
`127.0.0.1` is the guest itself. For a remote server, every egress bridge port
and intervening network link must support the same MTU. Configure the physical
bridge member as well only in that case.

The S3 smoke suites use an 8000-byte MTU by default. Override it with
`TCPFS_MTU`, select the guest interface with `TCPFS_S3_IFACE`, or select the
host bridge with `TCPFS_S3_BRIDGE`. The runner rejects a bridge whose MTU is
smaller than the requested guest MTU.
