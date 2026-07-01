#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Small, deterministic NFSv4.0 server used by the tcpfs smoke tests."""

import argparse
import os
import signal
import socket
import struct
import threading
import time


RPC_CALL = 0
RPC_REPLY = 1
RPC_MSG_ACCEPTED = 0
RPC_AUTH_NULL = 0
RPC_AUTH_SYS = 1
RPC_SUCCESS = 0
RPC_VERSION = 2
NFS_PROGRAM = 100003
NFS_VERSION = 4
NFS_COMPOUND = 1

NFS_OK = 0
NFSERR_NOENT = 2
NFSERR_NOTDIR = 20
NFSERR_ISDIR = 21
NFSERR_NOTSUPP = 10004

OP_GETATTR = 9
OP_LOOKUP = 15
OP_PUTROOTFH = 24
OP_READ = 25
OP_READDIR = 26

FATTR_TYPE = 1 << 1
FATTR_SIZE = 1 << 4
FATTR_FILEID = 1 << 20
FATTR_MODE = 1 << 1

NF4REG = 1
NF4DIR = 2

HELLO_DATA = b"hello from tcpfs nfs\n"
NOTE_DATA = b"nested tcpfs nfs file\n"
DIRECT_DATA = bytes((index * 31 + 7) & 0xFF for index in range(8192))


class XdrError(Exception):
    """Raised for a malformed or unsupported fixture request."""


class XdrReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, length):
        end = self.pos + length
        if length < 0 or end > len(self.data):
            raise XdrError("truncated XDR value")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def opaque(self):
        length = self.u32()
        value = self.take(length)
        self.take((-length) & 3)
        return value

    def bitmap(self):
        count = self.u32()
        if count > 3:
            raise XdrError("oversized attribute bitmap")
        return [self.u32() for _ in range(count)]


def xdr_u32(value):
    return struct.pack(">I", value)


def xdr_u64(value):
    return struct.pack(">Q", value)


def xdr_opaque(value):
    return xdr_u32(len(value)) + value + b"\0" * ((-len(value)) & 3)


def xdr_bitmap(words):
    words = list(words)
    while words and not words[-1]:
        words.pop()
    return xdr_u32(len(words)) + b"".join(xdr_u32(word) for word in words)


class Node:
    def __init__(self, fileid, data=None):
        self.fileid = fileid
        self.data = data

    @property
    def is_dir(self):
        return self.data is None

    @property
    def size(self):
        return 0 if self.is_dir else len(self.data)


NODES = {
    "/": Node(1),
    "/export": Node(2),
    "/export/hello.txt": Node(3, HELLO_DATA),
    "/export/empty.txt": Node(4, b""),
    "/export/direct.bin": Node(5, DIRECT_DATA),
    "/export/nested": Node(6),
    "/export/nested/note.txt": Node(7, NOTE_DATA),
    "/export/slow.bin": Node(8, DIRECT_DATA),
}


def child_path(parent, name):
    decoded = name.decode("utf-8")
    if not decoded or "/" in decoded or decoded in (".", ".."):
        raise XdrError("invalid LOOKUP component")
    return "/" + decoded if parent == "/" else parent + "/" + decoded


def directory_entries(path):
    prefix = "/" if path == "/" else path + "/"
    entries = []
    for candidate, node in NODES.items():
        if not candidate.startswith(prefix) or candidate == path:
            continue
        suffix = candidate[len(prefix):]
        if "/" not in suffix:
            entries.append((suffix, node))
    return sorted(entries)


def encode_fattr(node, requested):
    requested0 = requested[0] if requested else 0
    requested1 = requested[1] if len(requested) > 1 else 0
    returned0 = requested0 & (FATTR_TYPE | FATTR_SIZE | FATTR_FILEID)
    returned1 = requested1 & FATTR_MODE
    values = bytearray()

    if returned0 & FATTR_TYPE:
        values += xdr_u32(NF4DIR if node.is_dir else NF4REG)
    if returned0 & FATTR_SIZE:
        values += xdr_u64(node.size)
    if returned0 & FATTR_FILEID:
        values += xdr_u64(node.fileid)
    if returned1 & FATTR_MODE:
        values += xdr_u32(0o555 if node.is_dir else 0o444)

    return xdr_bitmap((returned0, returned1)) + xdr_opaque(values)


def encode_readdir(node_path, requested, maxcount):
    payload = bytearray(xdr_u64(0))
    cookie = 1

    for name, node in directory_entries(node_path):
        entry = bytearray(xdr_u32(1))
        entry += xdr_u64(cookie)
        entry += xdr_opaque(name.encode("utf-8"))
        entry += encode_fattr(node, requested)
        if len(payload) + len(entry) + 8 > maxcount:
            break
        payload += entry
        cookie += 1

    payload += xdr_u32(0)
    payload += xdr_u32(1)
    return bytes(payload)


def decode_auth_sys(body):
    auth = XdrReader(body)
    auth.u32()
    auth.opaque()
    uid = auth.u32()
    gid = auth.u32()
    group_count = auth.u32()
    if group_count > 16:
        raise XdrError("too many AUTH_SYS groups")
    for _ in range(group_count):
        auth.u32()
    if uid != 0 or gid != 0:
        raise XdrError("fixture requires AUTH_SYS uid/gid 0")
    if auth.pos != len(body):
        raise XdrError("trailing AUTH_SYS data")


def decode_call(data):
    reader = XdrReader(data)
    xid = reader.u32()
    if reader.u32() != RPC_CALL:
        raise XdrError("not an RPC call")
    if reader.u32() != RPC_VERSION:
        raise XdrError("unsupported RPC version")
    if reader.u32() != NFS_PROGRAM or reader.u32() != NFS_VERSION:
        raise XdrError("unsupported RPC program")
    if reader.u32() != NFS_COMPOUND:
        raise XdrError("unsupported NFS procedure")

    auth_flavor = reader.u32()
    auth_body = reader.opaque()
    if auth_flavor != RPC_AUTH_SYS:
        raise XdrError("expected AUTH_SYS")
    decode_auth_sys(auth_body)
    if reader.u32() != RPC_AUTH_NULL or reader.opaque():
        raise XdrError("expected an AUTH_NULL verifier")

    tag = reader.opaque()
    if reader.u32() != 0:
        raise XdrError("fixture only supports NFSv4.0")
    op_count = reader.u32()
    if not op_count or op_count > 66:
        raise XdrError("invalid COMPOUND operation count")

    current = "/"
    compound_status = NFS_OK
    results = []
    summary = []

    for _ in range(op_count):
        op = reader.u32()
        status = NFS_OK
        result = b""

        if op == OP_PUTROOTFH:
            current = "/"
        elif op == OP_LOOKUP:
            node = NODES.get(current)
            name = reader.opaque()
            if not node or not node.is_dir:
                status = NFSERR_NOTDIR
            else:
                candidate = child_path(current, name)
                if candidate not in NODES:
                    status = NFSERR_NOENT
                else:
                    current = candidate
        elif op == OP_GETATTR:
            requested = reader.bitmap()
            node = NODES.get(current)
            if not node:
                status = NFSERR_NOENT
            else:
                result = encode_fattr(node, requested)
        elif op == OP_READDIR:
            reader.u64()
            reader.take(8)
            reader.u32()
            maxcount = reader.u32()
            requested = reader.bitmap()
            node = NODES.get(current)
            if not node:
                status = NFSERR_NOENT
            elif not node.is_dir:
                status = NFSERR_NOTDIR
            else:
                result = encode_readdir(current, requested, maxcount)
        elif op == OP_READ:
            reader.take(16)
            offset = reader.u64()
            count = reader.u32()
            node = NODES.get(current)
            if not node:
                status = NFSERR_NOENT
            elif node.is_dir:
                status = NFSERR_ISDIR
            else:
                chunk = node.data[offset:offset + count]
                eof = offset + len(chunk) >= len(node.data)
                result = xdr_u32(1 if eof else 0) + xdr_opaque(chunk)
        else:
            status = NFSERR_NOTSUPP

        results.append(xdr_u32(op) + xdr_u32(status) + result)
        summary.append(str(op))
        if status:
            compound_status = status
            break

    compound = xdr_u32(compound_status) + xdr_opaque(tag)
    compound += xdr_u32(len(results)) + b"".join(results)
    rpc = xdr_u32(xid) + xdr_u32(RPC_REPLY) + xdr_u32(RPC_MSG_ACCEPTED)
    rpc += xdr_u32(RPC_AUTH_NULL) + xdr_u32(0) + xdr_u32(RPC_SUCCESS)
    return rpc + compound, current, ",".join(summary)


def recv_exact(conn, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise XdrError("connection closed during request")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_fragmented(conn, payload):
    record = xdr_u32(0x80000000 | len(payload)) + payload
    sizes = (2, 1, 5, 3, 11, 7, 17, 29, 53, 97, 193)
    offset = 0
    index = 0

    while offset < len(record):
        size = sizes[index % len(sizes)]
        conn.sendall(record[offset:offset + size])
        offset += size
        index += 1
        time.sleep(0.001)

    return index


def serve_connection(conn, peer):
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        marker = struct.unpack(">I", recv_exact(conn, 4))[0]
        if not marker & 0x80000000:
            raise XdrError("multi-fragment request is unsupported")
        length = marker & 0x7FFFFFFF
        if not length or length > 4096:
            raise XdrError("invalid RPC record length")
        response, path, operations = decode_call(recv_exact(conn, length))
        print(f"request peer={peer[0]}:{peer[1]} path={path} ops={operations}",
              flush=True)
        delayed = path == "/export/slow.bin" and operations.endswith(",25")
        if delayed:
            print(f"response delayed path={path}", flush=True)
            time.sleep(1)
        try:
            fragments = send_fragmented(conn, response)
        except (BrokenPipeError, ConnectionResetError):
            if not delayed:
                raise
            print(f"response cancelled path={path}", flush=True)
            return
        print(f"response path={path} bytes={len(response)} "
              f"fragments={fragments}", flush=True)
    except (BrokenPipeError, ConnectionResetError, XdrError) as error:
        print(f"request error: {error}", flush=True)
    finally:
        conn.close()


def run_server(address, port, ready_file):
    stopping = threading.Event()

    def stop(_signum, _frame):
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.listen()
        listener.settimeout(0.2)
        if ready_file:
            with open(ready_file, "w", encoding="ascii") as ready:
                ready.write(f"{address}:{port}\n")
        print(f"ready address={address} port={port}", flush=True)

        while not stopping.is_set():
            try:
                conn, peer = listener.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(target=serve_connection,
                                      args=(conn, peer), daemon=True)
            thread.start()

    if ready_file:
        try:
            os.unlink(ready_file)
        except FileNotFoundError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=20490)
    parser.add_argument("--ready-file")
    parser.add_argument("--write-expected")
    args = parser.parse_args()

    if args.write_expected:
        with open(args.write_expected, "wb") as expected:
            expected.write(DIRECT_DATA)
        return
    run_server(args.address, args.port, args.ready_file)


if __name__ == "__main__":
    main()
