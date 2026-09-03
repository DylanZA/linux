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

Current limitations
===================

datafs does not implement writes, cache revalidation, failover, or overlapping
ordinary requests.
