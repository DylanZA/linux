# datafs Project Guide

This is a Linux kernel tree. These instructions cover datafs, its shared BPF
protocol, TCP devmem support, Rust tools, smoke tests, and benchmarks. Preserve
unrelated worktree changes and follow normal kernel review standards.

## Architecture

datafs is an experimental read-only netfslib filesystem in `fs/datafs`.
It supports directories, metadata, buffered reads, direct reads, and one
filesystem-specific io_uring TCP-devmem receive command. BPF `tcpfs_ops`
struct-ops providers implement all wire-protocol framing and parsing. The
`tcpfs_*` type and kfunc names are retained as the shared protocol ABI; there is
no tcpfs filesystem or tcpfs userspace toolchain.

Netfslib drives ordinary buffered and direct read requests. datafs owns the
ordinary bounded TCP connection pool behind those callbacks because netfslib
does not manage sockets. The TCP-devmem command uses a separate userspace-owned
pool: BPF loans an established, flow-steered SOCKMAP socket to the kernel and
receives it back only after userspace returns every published dma-buf token.

Keep these boundaries strict:

- `fs/datafs` and `include/linux/datafs.h` contain no S3, HTTP, XML, NFS, RPC,
  XDR, SMB, or NTLM protocol knowledge.
- Keep `include/linux/datafs.h` and `datafs_tools/datafs_bpf.h` synchronized.
- The io_uring command never blocks on socket I/O or spawns a transport thread.
  Socket callbacks and timers schedule io_uring task work.
- Userspace owns devmem flow steering and loan-socket pool concurrency. There
  is no datafs `rx_queue=` mount option.
- datafs is read-only; its TCP-devmem command requires `O_DIRECT` and CQE32 or
  mixed CQEs.

Run the protocol boundary check; it must print nothing:

```sh
rg -n "datafs_s3|MinIO|ListBucket|<Key>|NFS_OP_|xdr|SMB2_|NTLMSSP" \
  fs/datafs include/linux/datafs.h include/uapi/linux/datafs.h
```

## TCP Devmem Command

`DATAFS_URING_CMD_RECV_DEVMEM` stores flags and the offset/token start in a
`struct datafs_uring_devmem_cmd` in `sqe->cmd` and reuses these SQE fields:

```text
len                 read length or DONTNEED token count
buf_group           host fallback group or socket-loan ID
zcrx_ifq_idx bits   netdev RX dma-buf binding ID
cmd.offset          file offset or DONTNEED token start
cmd.flags           DATAFS_URING_F_WAIT_SOCKET or DEVMEM_DONTNEED
```

File-data dma-buf fragments are posted as CQE32 entries containing
`struct datafs_uring_devmem_cqe`; linear fallback uses a provided-buffer CQE.
Extent CQEs carry `IORING_CQE_F_MORE`, and the terminal CQE reports the byte
count or error. Userspace must return all published tokens with
`DATAFS_URING_F_DEVMEM_DONTNEED` before the provider socket is returned.

## Code Map

- `fs/datafs/`: VFS, netfs callbacks, ordinary TCP pool, BPF registration, and
  the nonblocking TCP-devmem state machine.
- `include/linux/datafs.h`: shared BPF callback protocol ABI.
- `include/uapi/linux/datafs.h`: datafs io_uring command and CQE32 ABI.
- `net/core/devmem.c`, `net/ipv4/tcp.c`: TCP device-memory receive support.
- `datafs_tools/`: Rust loaders, fixtures, BPF providers, smoke tests, and
  benchmark clients. BPF bytecode remains C and VM orchestration remains shell.
- `benchmarks.md`: append-only measured results.

## Code Conventions

Non-obvious functions (methods) must carry a doc comment directly above the
definition, in the kernel `/** ... */` style documented in
`Documentation/process/coding-style.rst`. A function comment names the
function, explains what it does and why, documents each non-trivial parameter
with an `@param`/`@name` line, and states the `Return:` contract when
applicable. This applies to every added function in `fs/datafs/` and the
datafs-related core kernel changes (`net/*`, `io_uring/*`, headers), and should
be kept when editing those files. Trivial accessors and thin wrappers may use a
one-line `/** ... */` comment instead. Never add a doc comment that merely
restates the function name; it must add useful intent or context.

## Checks

Expected paths are `/home/dylan/dev/linux`, `/home/dylan/dev/liburing`, and
`/home/dylan/dev/virtme-ng/vng`.

```sh
make -j4
make W=1 -j4 fs/datafs/datafs.o net/core/sock_map.o net/core/devmem.o \
  net/ipv4/tcp.o
make -C datafs_tools check
git diff --check
```

Run relevant patches through `scripts/checkpatch.pl --strict`. Inspect complete
guest dmesg output for warnings, lock errors, refcount errors, and crashes.
Repository VM runners are bounded by `timeout 60`:

```sh
./datafs_tools/run_datafs_smoke.sh datafs-nfs
./datafs_tools/run_datafs_smoke.sh datafs-smb
./datafs_tools/run_datafs_smoke.sh datafs-s3
./datafs_tools/run_datafs_smoke.sh datafs-s3-devmem
```

The NFS and SMB fixtures are self-contained. S3 defaults to
`192.168.1.238:9000/publicbucket/out.data`, `br0`/`eth0`, and MTU 32000.

## Benchmark Recording

After receive, CQE, socket, dma-buf, or network changes:

1. Require all relevant smoke tests to pass.
2. Run `./datafs_tools/run_datafs_benchmark.sh`.
3. Prepend the result to `benchmarks.md`; never replace older runs.
4. Record commit, dirty state, endpoint/object, VM resources, MTU, length,
   iterations, fragments, times, and MiB/s for devmem, direct `pread`, buffered
   `pread`, and raw HTTP.
5. State that a single VM run is noisy; do not report only the fastest result.

The runner fixes MTU at 32000 and length at 1 GiB and uses a 60-second VM
timeout. Current measurements and historical tcpfs results are retained in
`benchmarks.md`.
