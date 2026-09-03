// SPDX-License-Identifier: GPL-2.0

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const OP_GETATTR: u32 = 9;
const OP_LOOKUP: u32 = 15;
const OP_PUTROOTFH: u32 = 24;
const OP_READ: u32 = 25;
const OP_READDIR: u32 = 26;
const FATTR_TYPE: u32 = 1 << 1;
const FATTR_SIZE: u32 = 1 << 4;
const FATTR_FILEID: u32 = 1 << 20;
const FATTR_MODE: u32 = 1 << 1;
const NFSERR_NOENT: u32 = 2;
const NFSERR_NOTDIR: u32 = 20;
const NFSERR_ISDIR: u32 = 21;
const NFSERR_NOTSUPP: u32 = 10004;

fn direct_data() -> Vec<u8> {
    (0..8192).map(|index| (index * 31 + 7) as u8).collect()
}
fn file_data(path: &str) -> Option<Vec<u8>> {
    match path {
        "/export/hello.txt" => Some(b"hello from datafs nfs\n".to_vec()),
        "/export/empty.txt" => Some(Vec::new()),
        "/export/direct.bin" | "/export/slow.bin" => Some(direct_data()),
        "/export/nested/note.txt" => Some(b"nested datafs nfs file\n".to_vec()),
        _ => None,
    }
}
fn is_dir(path: &str) -> bool {
    matches!(path, "/" | "/export" | "/export/nested")
}
fn exists(path: &str) -> bool {
    is_dir(path) || file_data(path).is_some()
}
fn file_id(path: &str) -> u64 {
    match path {
        "/" => 1,
        "/export" => 2,
        "/export/hello.txt" => 3,
        "/export/empty.txt" => 4,
        "/export/direct.bin" => 5,
        "/export/nested" => 6,
        "/export/nested/note.txt" => 7,
        "/export/slow.bin" => 8,
        _ => 0,
    }
}

struct Xdr<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Xdr<'a> {
    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(length)
            .filter(|v| *v <= self.data.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated XDR value"))?;
        let value = &self.data[self.pos..end];
        self.pos = end;
        Ok(value)
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn opaque(&mut self) -> io::Result<&'a [u8]> {
        let length = self.u32()? as usize;
        let value = self.take(length)?;
        self.take((4 - length % 4) % 4)?;
        Ok(value)
    }
    fn bitmap(&mut self) -> io::Result<Vec<u32>> {
        let count = self.u32()? as usize;
        if count > 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized bitmap",
            ));
        }
        (0..count).map(|_| self.u32()).collect()
    }
}

fn u32be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}
fn u64be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}
fn opaque(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(u32be(value.len() as u32));
    out.extend_from_slice(value);
    out.resize(out.len().next_multiple_of(4), 0);
    out
}
fn bitmap(mut words: Vec<u32>) -> Vec<u8> {
    while words.last() == Some(&0) {
        words.pop();
    }
    let mut out = Vec::from(u32be(words.len() as u32));
    for word in words {
        out.extend_from_slice(&u32be(word));
    }
    out
}

fn attributes(path: &str, requested: &[u32]) -> Vec<u8> {
    let requested0 = requested.first().copied().unwrap_or(0);
    let requested1 = requested.get(1).copied().unwrap_or(0);
    let returned0 = requested0 & (FATTR_TYPE | FATTR_SIZE | FATTR_FILEID);
    let returned1 = requested1 & FATTR_MODE;
    let mut values = Vec::new();
    if returned0 & FATTR_TYPE != 0 {
        values.extend_from_slice(&u32be(if is_dir(path) { 2 } else { 1 }));
    }
    if returned0 & FATTR_SIZE != 0 {
        values.extend_from_slice(&u64be(file_data(path).map_or(0, |v| v.len()) as u64));
    }
    if returned0 & FATTR_FILEID != 0 {
        values.extend_from_slice(&u64be(file_id(path)));
    }
    if returned1 & FATTR_MODE != 0 {
        values.extend_from_slice(&u32be(if is_dir(path) { 0o555 } else { 0o444 }));
    }
    let mut out = bitmap(vec![returned0, returned1]);
    out.extend(opaque(&values));
    out
}

fn children(path: &str) -> Vec<(&'static str, &'static str)> {
    match path {
        "/" => vec![("export", "/export")],
        "/export" => vec![
            ("direct.bin", "/export/direct.bin"),
            ("empty.txt", "/export/empty.txt"),
            ("hello.txt", "/export/hello.txt"),
            ("nested", "/export/nested"),
            ("slow.bin", "/export/slow.bin"),
        ],
        "/export/nested" => vec![("note.txt", "/export/nested/note.txt")],
        _ => Vec::new(),
    }
}

fn readdir(path: &str, requested: &[u32], maxcount: usize) -> Vec<u8> {
    let mut out = Vec::from(u64be(0));
    let mut cookie = 1u64;
    for (name, child) in children(path) {
        let mut entry = Vec::from(u32be(1));
        entry.extend_from_slice(&u64be(cookie));
        entry.extend(opaque(name.as_bytes()));
        entry.extend(attributes(child, requested));
        if out.len() + entry.len() + 8 > maxcount {
            break;
        }
        out.extend(entry);
        cookie += 1;
    }
    out.extend_from_slice(&u32be(0));
    out.extend_from_slice(&u32be(1));
    out
}

fn decode_auth(reader: &mut Xdr<'_>) -> io::Result<()> {
    if reader.u32()? != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected AUTH_SYS",
        ));
    }
    let body = reader.opaque()?;
    let mut auth = Xdr { data: body, pos: 0 };
    auth.u32()?;
    auth.opaque()?;
    let uid = auth.u32()?;
    let gid = auth.u32()?;
    let groups = auth.u32()?;
    if groups > 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many groups",
        ));
    }
    for _ in 0..groups {
        auth.u32()?;
    }
    if uid != 0 || gid != 0 || auth.pos != body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture requires AUTH_SYS uid/gid 0",
        ));
    }
    if reader.u32()? != 0 || !reader.opaque()?.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected AUTH_NULL verifier",
        ));
    }
    Ok(())
}

fn decode_call(data: &[u8]) -> io::Result<(Vec<u8>, String, String)> {
    let mut reader = Xdr { data, pos: 0 };
    let xid = reader.u32()?;
    if reader.u32()? != 0
        || reader.u32()? != 2
        || reader.u32()? != 100003
        || reader.u32()? != 4
        || reader.u32()? != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported RPC call",
        ));
    }
    decode_auth(&mut reader)?;
    let tag = reader.opaque()?.to_vec();
    if reader.u32()? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only NFSv4.0 is supported",
        ));
    }
    let count = reader.u32()?;
    if count == 0 || count > 66 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid operation count",
        ));
    }
    let mut current = "/".to_string();
    let mut status = 0u32;
    let mut results = Vec::new();
    let mut summary = Vec::new();
    let mut result_count = 0u32;
    for _ in 0..count {
        let operation = reader.u32()?;
        let mut op_status = 0u32;
        let mut payload = Vec::new();
        match operation {
            OP_PUTROOTFH => current = "/".into(),
            OP_LOOKUP => {
                let name = std::str::from_utf8(reader.opaque()?).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid lookup name")
                })?;
                if !is_dir(&current) {
                    op_status = NFSERR_NOTDIR;
                } else if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid lookup component",
                    ));
                } else {
                    let candidate = if current == "/" {
                        format!("/{name}")
                    } else {
                        format!("{current}/{name}")
                    };
                    if exists(&candidate) {
                        current = candidate;
                    } else {
                        op_status = NFSERR_NOENT;
                    }
                }
            }
            OP_GETATTR => {
                let requested = reader.bitmap()?;
                if exists(&current) {
                    payload = attributes(&current, &requested);
                } else {
                    op_status = NFSERR_NOENT;
                }
            }
            OP_READDIR => {
                reader.u64()?;
                reader.take(8)?;
                reader.u32()?;
                let maxcount = reader.u32()? as usize;
                let requested = reader.bitmap()?;
                if !exists(&current) {
                    op_status = NFSERR_NOENT;
                } else if !is_dir(&current) {
                    op_status = NFSERR_NOTDIR;
                } else {
                    payload = readdir(&current, &requested, maxcount);
                }
            }
            OP_READ => {
                reader.take(16)?;
                let offset = reader.u64()? as usize;
                let count = reader.u32()? as usize;
                if !exists(&current) {
                    op_status = NFSERR_NOENT;
                } else if is_dir(&current) {
                    op_status = NFSERR_ISDIR;
                } else {
                    let data = file_data(&current).unwrap();
                    let start = offset.min(data.len());
                    let end = offset.saturating_add(count).min(data.len());
                    payload.extend_from_slice(&u32be((end == data.len()) as u32));
                    payload.extend(opaque(&data[start..end]));
                }
            }
            _ => op_status = NFSERR_NOTSUPP,
        }
        results.extend_from_slice(&u32be(operation));
        results.extend_from_slice(&u32be(op_status));
        results.extend(payload);
        summary.push(operation.to_string());
        result_count += 1;
        if op_status != 0 {
            status = op_status;
            break;
        }
    }
    let mut compound = Vec::from(u32be(status));
    compound.extend(opaque(&tag));
    compound.extend_from_slice(&u32be(result_count));
    compound.extend(results);
    let mut rpc = Vec::from(u32be(xid));
    for value in [1, 0, 0, 0, 0] {
        rpc.extend_from_slice(&u32be(value));
    }
    rpc.extend(compound);
    Ok((rpc, current, summary.join(",")))
}

fn send_fragmented(stream: &mut TcpStream, payload: &[u8]) -> io::Result<usize> {
    let mut record = Vec::from(u32be(0x8000_0000 | payload.len() as u32));
    record.extend_from_slice(payload);
    let sizes = [2, 1, 5, 3, 11, 7, 17, 29, 53, 97, 193];
    let mut offset = 0;
    let mut index = 0;
    while offset < record.len() {
        let end = (offset + sizes[index % sizes.len()]).min(record.len());
        stream.write_all(&record[offset..end])?;
        offset = end;
        index += 1;
        thread::sleep(Duration::from_millis(1));
    }
    Ok(index)
}

fn handle_request(stream: &mut TcpStream, peer: &str) -> io::Result<bool> {
    let mut marker = [0; 4];
    if let Err(error) = stream.read_exact(&mut marker) {
        return if matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
        ) {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let marker = u32::from_be_bytes(marker);
    if marker & 0x8000_0000 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fragmented request unsupported",
        ));
    }
    let length = (marker & 0x7fff_ffff) as usize;
    if length == 0 || length > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid record length",
        ));
    }
    let mut request = vec![0; length];
    stream.read_exact(&mut request)?;
    let (response, path, operations) = decode_call(&request)?;
    println!("request peer={peer} path={path} ops={operations}");
    let delayed = path == "/export/slow.bin" && operations.ends_with(",25");
    if delayed {
        println!("response delayed path={path}");
        thread::sleep(Duration::from_secs(1));
    }
    match send_fragmented(stream, &response) {
        Ok(fragments) => println!(
            "response path={path} bytes={} fragments={fragments}",
            response.len()
        ),
        Err(error)
            if delayed
                && matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ) =>
        {
            println!("response cancelled path={path}")
        }
        Err(error) => return Err(error),
    }
    Ok(true)
}

fn handle(mut stream: TcpStream, peer: String) -> io::Result<()> {
    stream.set_nodelay(true)?;
    while handle_request(&mut stream, &peer)? {}
    Ok(())
}

fn main() -> io::Result<()> {
    let mut address = "127.0.0.1".to_string();
    let mut port = 20490u16;
    let mut ready = None::<PathBuf>;
    let mut expected = None::<PathBuf>;
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--address") => address = args.next().unwrap().to_string_lossy().into_owned(),
            Some("--port") => port = args.next().unwrap().to_string_lossy().parse().unwrap(),
            Some("--ready-file") => ready = args.next().map(PathBuf::from),
            Some("--write-expected") => expected = args.next().map(PathBuf::from),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid arguments",
                ));
            }
        }
    }
    if let Some(path) = expected {
        return fs::write(path, direct_data());
    }
    let listener = TcpListener::bind((address.as_str(), port))?;
    if let Some(path) = ready {
        fs::write(path, format!("{address}:{port}\n"))?;
    }
    println!("ready address={address} port={port}");
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let peer = stream
                    .peer_addr()
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                thread::spawn(move || {
                    if let Err(error) = handle(stream, peer) {
                        eprintln!("request error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("accept error: {error}"),
        }
    }
    Ok(())
}
