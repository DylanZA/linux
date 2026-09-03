# datafs NFSv4 sample

`datafs_nfs.bpf.c` is a read-only NFSv4.0 protocol implementation for datafs.
It supports lookup, getattr, readdir, and buffered/direct reads. The kernel
filesystem remains unaware of NFS and ONC RPC.

Build the BPF object and loader with:

```sh
make -C datafs_tools datafs_nfs.bpf.o datafs_nfs_loader
```

Start the loader and mount an export from the server's NFSv4 pseudo-filesystem
namespace. For an export visible as `/public`, use:

```sh
./datafs_tools/datafs_nfs_loader &
loader=$!
modprobe datafs
mkdir -p /tmp/datafs
mount -t datafs none /tmp/datafs \
  -o servers=192.0.2.1:2049,ops=datafs_nfs,arg=public,timeout_ms=5000,\
buf_size=4096,pool_size=8
```

An empty `arg=` addresses the NFSv4 pseudo-filesystem root. Leading and
trailing slashes in the argument are ignored.

The sample uses AUTH_SYS credentials with uid and gid 0, no supplementary
groups, and the NFSv4 anonymous stateid for reads. It opens a new TCP
connection for every request and supports a single RPC record fragment.
Individual reads are capped at 1 MiB and larger VFS reads complete as partial
reads. Readdir returns one bounded snapshot of up to 2 KiB of XDR data.

The sample does not implement NFSv4.1 sessions, RPCSEC_GSS, symlinks, ACLs,
file mutation, directory pagination, referrals, or transport recovery. Use it
only with a trusted NFS server and a read-only export.

Smoke test
----------

The repository includes a deterministic NFSv4 fixture that validates requests
and deliberately fragments replies across TCP writes. Run the complete NFS
smoke in a timeout-bounded virtme guest with:

```sh
./datafs_tools/run_datafs_smoke.sh datafs-nfs
```

The smoke asserts root and nested listings, attributes, empty-file EOF,
concurrent buffered reads, offset and full-file `O_DIRECT` reads, fragmented
replies, serial connection reuse, read-only behavior, rejected mount options,
clean teardown, and fatal dmesg diagnostics.

Run build and fixture checks without starting a VM with:

```sh
make -C datafs_tools check
```

The equivalent Makefile target is `smoke-nfs`.
