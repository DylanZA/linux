# datafs tools

This is the authoritative userspace toolchain for datafs. It contains Rust
loaders and fixtures, BPF protocol providers, and timeout-bounded shell smoke
and benchmark runners.

The S3, OpenAPI REST, NFSv4, and SMB2 protocol programs remain `.bpf.c` files
because they compile to BPF bytecode. Host-side loaders, fixture servers, the
TCP-devmem client, and the read benchmark are Rust. Builds use the cached
`libc` crate, in-tree libbpf, and the adjacent liburing checkout without
network access.

Build and validate everything with:

```bash
make -C datafs_tools
make -C datafs_tools check
```

Run the protocol and TCP-devmem suites with:

```bash
./datafs_tools/run_datafs_smoke.sh datafs-nfs
./datafs_tools/run_datafs_smoke.sh datafs-rest
./datafs_tools/run_datafs_smoke.sh datafs-smb
./datafs_tools/run_datafs_smoke.sh datafs-s3
./datafs_tools/run_datafs_smoke.sh datafs-s3-devmem
```

See `README.rest.md` for the OpenAPI-generated REST filesystem and its
`.schema` shadow tree.

The `tcpfs_*` structures and kfunc declarations in `datafs_bpf.h` are the
retained BPF protocol ABI. They do not imply that a tcpfs filesystem or tool is
still built.

The regular-read smoke paths also run `datafs_uring_read` to verify deferred
completion through an `IORING_OP_READ`.
