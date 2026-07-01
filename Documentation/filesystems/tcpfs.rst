.. SPDX-License-Identifier: GPL-2.0

=====
tcpfs
=====

tcpfs is a read-only filesystem whose request and response protocol is
implemented by a BPF ``struct_ops`` program.  The filesystem supplies paths,
offsets, and operation types to the program and transports the resulting
payload over TCP.  Protocol-specific parsing does not live in the filesystem
module.

Mount options
=============

The general mount form is::

  mount -t tcpfs none /mnt -o servers=ADDRESS:PORT,ops=NAME,arg=VALUE

``servers=``
  A comma-separated list of IPv4 addresses or bracketed IPv6 addresses with
  ports.  The current transport uses the first address in the list.

``ops=``
  The name of an attached ``tcpfs_ops`` BPF struct-ops instance.

``arg=``
  Opaque, protocol-specific mount data copied to each BPF request context.

``timeout_ms=``
  Synchronous socket and BPF-registration timeout in milliseconds.

``buf_size=``
  Receive look-ahead size.  It cannot exceed ``TCPFS_PAYLOAD_MAX``.

``buf_count=``
  Reserved buffer-pool sizing value.  The current implementation records the
  value but does not allocate per-buffer objects from it.

BPF operations
==============

The BPF program supplies callbacks to build and frame requests, unframe and
interpret replies, and optionally process unsolicited replies.  It also
selects one of these connection models:

``TCPFS_CONN_NEW``
  Open a connection for each request.

``TCPFS_CONN_SERIAL``
  Reuse one connection and serialize requests on it.

``TCPFS_CONN_OVERLAP``
  Allow overlapping requests.  This model is reserved and is not implemented
  by the transport yet.

The sample programs and loaders are in ``tcpfs_tools``.  They are examples,
not part of the userspace ABI.

I/O
===

Regular files support buffered and direct reads.  The io_uring command
``TCPFS_URING_CMD_READ_ZC`` requires a file opened with ``O_DIRECT``, a ring
created with ``IORING_SETUP_CQE32``, and a registered zero-copy receive queue.
Data CQEs carry ``IORING_CQE_F_MORE``; the final CQE reports the total byte
count or an error.

Current limitations
===================

tcpfs currently implements lookup, getattr, readdir, and read.  It does not
implement writes, cache revalidation, server failover, or overlapping
requests.  Async commands do not yet have a transport timer.  Directory
results are returned as a bounded snapshot by the BPF program.

Security
========

The attached BPF program controls the bytes sent to the configured servers
and interprets all replies.  Only trusted programs should be attached.  tcpfs
provides a plaintext TCP transport; authentication, integrity, and encryption
are protocol concerns and must be supplied by the BPF program or by a trusted
proxy.
