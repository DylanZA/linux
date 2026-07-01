# tcpfs NFSv4 sample

`tcpfs_nfs.bpf.c` is a read-only NFSv4.0 protocol implementation for tcpfs.
It supports lookup, getattr, readdir, buffered/direct reads, and tcpfs zero-copy
reads. The kernel filesystem remains unaware of NFS and ONC RPC.

Build the BPF object and loader with:

```sh
make -C tcpfs_tools tcpfs_nfs.bpf.o tcpfs_nfs_loader
```

Start the loader and mount an export from the server's NFSv4 pseudo-filesystem
namespace. For an export visible as `/public`, use:

```sh
./tcpfs_tools/tcpfs_nfs_loader &
loader=$!
modprobe tcpfs
mkdir -p /tmp/tcpfs
mount -t tcpfs none /tmp/tcpfs \
  -o servers=192.0.2.1:2049,ops=tcpfs_nfs,arg=public,timeout_ms=5000,\
buf_size=4096,buf_count=8
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
./tcpfs_tools/run_tcpfs_smoke.sh nfs
```

The smoke asserts root and nested listings, attributes, missing-path errors,
empty-file EOF, concurrent buffered and NODEV zero-copy reads, offset and
full-file `O_DIRECT` reads, offset and past-EOF zero-copy reads, fragmented
completion data and copy accounting, read-only behavior, rejected mount
options, asynchronous cancellation and follow-up I/O, duplicate BPF
registration, loader-detach lifetime, clean teardown, nested export arguments,
and a second mount after unloading and reloading the module.

Run build and fixture checks without starting a VM with:

```sh
make -C tcpfs_tools check
```

Equivalent Makefile targets for the VM suites are `smoke-nfs`,
`smoke-s3-nodev`, and `smoke-s3-nic`.
