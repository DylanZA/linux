# datafs Benchmarks

## Current result

Date: 2026-09-04

Commit: `2c1de4a5fc1da88769bf40c3f39ec9c89d27eb07`

The benchmark used the repository's standard runner and configuration:

- 4-vCPU, 4 GiB virtme/QEMU guest
- MinIO endpoint `192.168.1.238:9000`
- object `publicbucket/out.data`
- 1 GiB read length
- one iteration with no warmup
- MTU 32000 on `br0` and guest `eth0`
- software GRO enabled and hardware GRO disabled
- one userspace-owned socket loan
- one RX dma-buf binding on `eth0:0`
- 130-byte virtio-net host-memory prefix, covering the virtio header,
  Ethernet and VLAN headers, IPv6 header, and maximum TCP header

The `datafs-s3-devmem` smoke test passed before the benchmark:

```text
datafs smoke: PASS mode=datafs-s3-devmem iface=eth0 mtu=32000
```

### Throughput

| Method | Time | Throughput | Result |
|---|---:|---:|---|
| datafs device memory | 3.08 s | approximately 332.5 MiB/s | passed |
| datafs direct `pread` | 2773.608 ms | 369.194 MiB/s | passed |
| datafs buffered `pread` | more than 30 s | not valid | timed out |
| raw HTTP | not measured | not measured | not reached |

The runner stopped when buffered `pread` exceeded its 30-second timeout, so
this is a partial benchmark rather than a complete performance baseline. Raw
HTTP appears after buffered `pread` in the runner and was therefore not run.

### Device-memory accounting

| Metric | Value |
|---|---:|
| Total bytes | 1,073,741,824 |
| dma-buf bytes | 1,034,984,155 (96.391%) |
| Host bytes | 38,757,669 (3.609%) |
| Total fragments | 1,674,522 |
| dma-buf fragments | 928,807 |
| Host fragments | 745,715 |
| Tokens published and returned | 928,807 |

All published dma-buf tokens were returned. Host fragments represented 44.5%
of fragment CQEs but only 3.609% of bytes because they contain small readable
headers. Fragment counts must therefore not be used as a copied-byte ratio.

In this run, device-memory receive was approximately 10% slower than direct
`pread`. The high CQE count remains a likely source of overhead. A single VM
run is noisy, and the missing buffered and raw-HTTP results prevent a complete
comparison.

Historical tcpfs measurements are omitted because they cover a different
filesystem, receive ABI, buffer-ownership model, and userspace client.
