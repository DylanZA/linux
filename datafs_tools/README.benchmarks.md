# datafs Benchmarks

Build and run the fixed 1 GiB VM comparison:

```sh
make -C datafs_tools
datafs_tools/run_datafs_benchmark.sh
```

It compares the TCP-devmem io_uring command, datafs `O_DIRECT` and buffered
`pread`, and raw HTTP. Defaults are MTU 32000 and
`192.168.1.238:9000/publicbucket/out.data`; override endpoint components with
`DATAFS_S3_SERVER`, `DATAFS_S3_BUCKET`, and `DATAFS_S3_OBJECT`.

Compare an existing datafs mount and S3 FUSE mount with conventional reads:

```sh
FUSE_MNT=/tmp/s3fs datafs_tools/datafs_bench_compare_s3.sh \
  --file out.data --len 1073741824 --iters 1 --warmup 0 --csv
```

Use `datafs_bench_mount.sh` to create a datafs S3 mount first. The MinIO
address must be reachable from the guest; guest loopback is not host loopback.
