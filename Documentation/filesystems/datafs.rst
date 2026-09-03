.. SPDX-License-Identifier: GPL-2.0

======
datafs
======

datafs is an experimental read-only netfslib filesystem.  A BPF
``tcpfs_ops`` struct-ops program implements its wire protocol.  The filesystem
passes generic operation, path, offset, and length fields to BPF and transports
the resulting request over TCP; protocol-specific framing and parsing remain
outside the filesystem module.

Ordinary reads
==============

datafs implements lookup, getattr, directory enumeration, buffered reads, and
direct reads.  Netfslib manages the page cache and direct-I/O iterators.  The
phase-1 transport supports up to eight protocol continuation exchanges and
currently uses the first server from the mount's server list.  Providers using
``TCPFS_CONN_SERIAL`` share a bounded datafs connection pool; each connection
serves one request at a time and is discarded after a transport error.
``TCPFS_CONN_NEW`` providers continue to use a fresh connection per operation.
Netfslib drives read subrequests and page-cache integration; datafs owns this
ordinary transport pool because netfslib does not provide socket management.

The general mount form is::

  mount -t datafs none /mnt -o servers=ADDRESS:PORT,ops=NAME,arg=VALUE

``servers=`` is a comma-separated IPv4 or bracketed IPv6 server list, ``ops=``
names an attached ``tcpfs_ops`` BPF struct-ops instance, and ``arg=`` is opaque
data made available to that BPF provider.  ``timeout_ms=``, ``buf_size=``, and
``buf_count=`` sets the serial connection-pool limit and ``buf_size=`` limits
callback receive buffering.

TCP device-memory command
=========================

``DATAFS_URING_CMD_RECV_DEVMEM`` is available on a regular file opened with
``O_DIRECT``.  The io_uring must use CQE32 or mixed CQEs.  It stores flags and
the file offset in ``struct datafs_uring_devmem_cmd`` at ``sqe->cmd`` and uses::

  len                 requested bytes
  buf_group           PAGE_SIZE provided-buffer group for linear fallback
  zcrx_ifq_idx bits   netdev RX dma-buf binding ID
  cmd.offset          file offset
  cmd.flags           DATAFS_URING_F_WAIT_SOCKET or zero

The command privately interprets the existing ``zcrx_ifq_idx`` union storage
as a dma-buf binding ID; it does not add a datafs alias to generic io_uring
UAPI.

The BPF provider's ``loan_socket`` callback supplies an established TCP socket
whose flow is already steered to a device-memory-enabled interface queue.  The
helper removes the socket from the provider's SOCKMAP atomically.  Userspace
owns flow steering and connection-pool sizing, and must not use or close its
file descriptor while the socket is on loan.  Without
``DATAFS_URING_F_WAIT_SOCKET``, pool exhaustion returns ``-EAGAIN``; with it,
the command waits until another loan is returned or it is cancelled.

The command receives with ``MSG_SOCK_DEVMEM | MSG_DONTWAIT``.  When protocol
header bytes arrive in device memory, datafs posts a CQE32 copy request carrying
an opaque key, length, and dma-buf offset.  Userspace uses its exporter-specific
mechanism (for example, a CUDA device-to-host copy) to stage the bytes in a
registered host buffer, then submits ``DATAFS_URING_CMD_COPY_RESPONSE`` with
the key.  The original receive command resumes BPF parsing only after that
response, and datafs retains the networking token throughout the transfer.

File-data dma-buf fragments produce CQE32 entries with
``IORING_CQE_F_MORE``.  ``res`` is the valid extent length and the second CQE
contains ``struct datafs_uring_devmem_cqe``.  The owning socket-loan ID is in
the upper 16 bits of ``cqe->flags``.  Linear data is copied into a provided
buffer and also carries ``IORING_CQE_F_BUFFER``.  The terminal CQE omits
``IORING_CQE_F_MORE`` and reports the total byte count or an error.

Userspace returns each published dma-buf token with another
``DATAFS_URING_CMD_RECV_DEVMEM`` command carrying
``DATAFS_URING_F_DEVMEM_DONTNEED``.  In that form, ``buf_group`` is the mount
loan ID, the reused union slot is the binding ID, ``cmd.offset`` is the first
token, and ``len`` is the token count.  The filesystem retains the
socket after the read's terminal CQE until every token is returned; only then
does BPF reinsert the socket into its userspace-managed pool.

Current limitations
===================

Protocol continuations are not yet supported by this command.  The sample S3
provider currently demonstrates a
single flow-steered queue; userspace is responsible for configuring exact
flow steering before using multiple queues.  datafs does not implement writes,
cache revalidation, failover, or overlapping ordinary requests.
