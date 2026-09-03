// SPDX-License-Identifier: GPL-2.0

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;

const NEGOTIATE: u16 = 0;
const SESSION_SETUP: u16 = 1;
const TREE_CONNECT: u16 = 3;
const CREATE: u16 = 5;
const READ: u16 = 8;
const QUERY_DIRECTORY: u16 = 14;
const MORE_PROCESSING: u32 = 0xc000_0016;
const NAME_NOT_FOUND: u32 = 0xc000_0034;
const SESSION_ID: u64 = 0x1122_3344_5566_7788;
const TREE_ID: u32 = 0x1234;
const FILE_ID: u64 = 0xabcd_ef01_2345_6789;

fn direct_data() -> Vec<u8> {
    (0..8192).map(|index| (index * 17 + 3) as u8).collect()
}
fn files() -> HashMap<&'static str, Vec<u8>> {
    HashMap::from([
        ("hello.txt", b"hello from datafs smb\n".to_vec()),
        ("direct.bin", direct_data()),
        ("nested/note.txt", b"nested datafs smb file\n".to_vec()),
    ])
}
fn is_directory(path: &str) -> bool {
    path.is_empty() || path == "nested"
}

fn le16(data: &[u8], offset: usize) -> io::Result<u16> {
    data.get(offset..offset + 2)
        .map(|v| u16::from_le_bytes(v.try_into().unwrap()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated u16"))
}
fn le32(data: &[u8], offset: usize) -> io::Result<u32> {
    data.get(offset..offset + 4)
        .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated u32"))
}
fn le64(data: &[u8], offset: usize) -> io::Result<u64> {
    data.get(offset..offset + 8)
        .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated u64"))
}
fn put16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn receive(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported NetBIOS message",
        ));
    }
    let length = u32::from_be_bytes(header) as usize;
    let mut packet = vec![0; length];
    stream.read_exact(&mut packet)?;
    Ok(packet)
}

fn response_header(
    request: &[u8],
    status: u32,
    command: u16,
    tree: Option<u32>,
    session: Option<u64>,
) -> io::Result<Vec<u8>> {
    let mut result = vec![0; 64];
    result[..4].copy_from_slice(b"\xfeSMB");
    put16(&mut result, 4, 64);
    put16(&mut result, 6, 1);
    put32(&mut result, 8, status);
    put16(&mut result, 12, command);
    put16(&mut result, 14, 1);
    put32(&mut result, 16, 1);
    put64(&mut result, 24, le64(request, 24)?);
    put32(&mut result, 32, 0xfeff);
    put32(&mut result, 36, tree.unwrap_or(le32(request, 36)?));
    put64(&mut result, 40, session.unwrap_or(le64(request, 40)?));
    Ok(result)
}

fn send(
    stream: &mut TcpStream,
    request: &[u8],
    status: u32,
    command: u16,
    body: &[u8],
    tree: Option<u32>,
    session: Option<u64>,
) -> io::Result<()> {
    let mut packet = response_header(request, status, command, tree, session)?;
    packet.extend_from_slice(body);
    let mut header = (packet.len() as u32).to_be_bytes();
    header[0] = 0;
    stream.write_all(&header)?;
    stream.write_all(&packet)
}

fn negotiate_body() -> Vec<u8> {
    let mut b = vec![0; 64];
    put16(&mut b, 0, 65);
    put16(&mut b, 2, 1);
    put16(&mut b, 4, 0x0210);
    b[8..24].copy_from_slice(b"datafs-smb-servr");
    for (o, v) in [(24, 0), (28, 65536), (32, 65536), (36, 65536)] {
        put32(&mut b, o, v);
    }
    b
}
fn session_body() -> Vec<u8> {
    let mut b = vec![0; 8];
    put16(&mut b, 0, 9);
    put16(&mut b, 4, 72);
    b
}
fn tree_body() -> Vec<u8> {
    let mut b = vec![0; 16];
    put16(&mut b, 0, 16);
    b[2] = 1;
    put32(&mut b, 8, 0x001f_01ff);
    put32(&mut b, 12, 0x001f_01ff);
    b
}

fn decode_path(request: &[u8]) -> io::Result<String> {
    let offset = le16(request, 108)? as usize;
    let length = le16(request, 110)? as usize;
    let raw = request
        .get(offset..offset + length)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad create path"))?;
    let words: Vec<u16> = raw
        .chunks_exact(2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .collect();
    Ok(String::from_utf16(&words)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad UTF-16 path"))?
        .replace('\\', "/"))
}

fn create_body(path: &str, data: &HashMap<&str, Vec<u8>>) -> Vec<u8> {
    let directory = is_directory(path);
    let size = data.get(path).map_or(0, Vec::len) as u64;
    let mut b = vec![0; 88];
    put16(&mut b, 0, 89);
    put32(&mut b, 4, 1);
    put64(&mut b, 40, size);
    put64(&mut b, 48, size);
    put32(&mut b, 56, if directory { 0x10 } else { 0x80 });
    put64(&mut b, 64, FILE_ID);
    put64(&mut b, 72, !FILE_ID);
    b
}

fn directory_record(name: &str, directory: bool, last: bool) -> Vec<u8> {
    let encoded: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let length = 64 + encoded.len();
    let aligned = length.next_multiple_of(8);
    let mut b = vec![0; aligned];
    put32(&mut b, 0, if last { 0 } else { aligned as u32 });
    put32(&mut b, 56, if directory { 0x10 } else { 0x80 });
    put32(&mut b, 60, encoded.len() as u32);
    b[64..64 + encoded.len()].copy_from_slice(&encoded);
    b
}

fn directory_body(path: &str) -> Vec<u8> {
    let entries: &[(&str, bool)] = if path.is_empty() {
        &[
            (".", true),
            ("..", true),
            ("direct.bin", false),
            ("hello.txt", false),
            ("nested", true),
        ]
    } else {
        &[(".", true), ("..", true), ("note.txt", false)]
    };
    let mut records = Vec::new();
    for (index, (name, directory)) in entries.iter().enumerate() {
        records.extend(directory_record(
            name,
            *directory,
            index + 1 == entries.len(),
        ));
    }
    let mut b = vec![0; 8];
    put16(&mut b, 0, 9);
    put16(&mut b, 2, 72);
    put32(&mut b, 4, records.len() as u32);
    b.extend(records);
    b
}

fn read_body(request: &[u8], path: &str, data: &HashMap<&str, Vec<u8>>) -> io::Result<Vec<u8>> {
    let length = le32(request, 68)? as usize;
    let offset = le64(request, 72)? as usize;
    let file = data
        .get(path)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "file not found"))?;
    let chunk = &file[offset.min(file.len())..(offset + length).min(file.len())];
    let mut b = vec![0; 16];
    put16(&mut b, 0, 17);
    b[2] = 80;
    put32(&mut b, 4, chunk.len() as u32);
    b.extend_from_slice(chunk);
    Ok(b)
}

fn handle(mut stream: TcpStream, peer: String) -> io::Result<()> {
    let data = files();
    let mut setup_round = 0;
    let mut path = String::new();
    loop {
        let request = match receive(&mut stream) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if request.len() < 64 || &request[..4] != b"\xfeSMB" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SMB2 header",
            ));
        }
        let command = le16(&request, 12)?;
        println!("request peer={peer} command={command}");
        match command {
            NEGOTIATE => send(
                &mut stream,
                &request,
                0,
                command,
                &negotiate_body(),
                Some(0),
                Some(0),
            )?,
            SESSION_SETUP => {
                setup_round += 1;
                send(
                    &mut stream,
                    &request,
                    if setup_round == 1 { MORE_PROCESSING } else { 0 },
                    command,
                    &session_body(),
                    Some(0),
                    Some(SESSION_ID),
                )?;
            }
            TREE_CONNECT => send(
                &mut stream,
                &request,
                0,
                command,
                &tree_body(),
                Some(TREE_ID),
                Some(SESSION_ID),
            )?,
            CREATE => {
                path = decode_path(&request)?;
                if !is_directory(&path) && !data.contains_key(path.as_str()) {
                    send(
                        &mut stream,
                        &request,
                        NAME_NOT_FOUND,
                        command,
                        &[],
                        None,
                        None,
                    )?;
                } else {
                    send(
                        &mut stream,
                        &request,
                        0,
                        command,
                        &create_body(&path, &data),
                        None,
                        None,
                    )?;
                }
            }
            QUERY_DIRECTORY => send(
                &mut stream,
                &request,
                0,
                command,
                &directory_body(&path),
                None,
                None,
            )?,
            READ => send(
                &mut stream,
                &request,
                0,
                command,
                &read_body(&request, &path, &data)?,
                None,
                None,
            )?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported SMB2 command {command}"),
                ));
            }
        }
    }
}

fn main() -> io::Result<()> {
    let mut address = "127.0.0.1".to_string();
    let mut port = 20445u16;
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
        fs::write(path, b"ready\n")?;
    }
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let peer = stream
                    .peer_addr()
                    .map(|p| p.ip().to_string())
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
