// SPDX-License-Identifier: GPL-2.0

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

const HEADER_MAX: usize = 64 * 1024;

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub content_length: Option<usize>,
}

pub trait FilesystemDispatch: Send + Sync + 'static {
    fn internal(&self, kind: &str, path: &str, range: Option<(usize, usize)>) -> Response;
    fn upstream(&self) -> &str;
}

pub struct Server {
    address: SocketAddr,
}

fn read_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Ok(request);
        }
        request.extend_from_slice(&buffer[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
        if request.len() >= HEADER_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request headers are too large",
            ));
        }
    }
}

fn request_parts(request: &[u8]) -> io::Result<(&str, &str, Vec<&str>)> {
    let text = std::str::from_utf8(request)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 HTTP request"))?;
    let mut lines = text.split("\r\n");
    let mut first = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HTTP request"))?
        .split_ascii_whitespace();
    let method = first.next().unwrap_or_default();
    let target = first.next().unwrap_or_default();
    if method.is_empty() || target.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTP request line",
        ));
    }
    Ok((
        method,
        target,
        lines.take_while(|line| !line.is_empty()).collect(),
    ))
}

fn range(headers: &[&str]) -> Option<(usize, usize)> {
    let value = headers.iter().find_map(|line| {
        line.strip_prefix("Range: bytes=")
            .or_else(|| line.strip_prefix("range: bytes="))
    })?;
    let (start, end) = value.split_once('-')?;
    Some((start.parse().ok()?, end.parse().ok()?))
}

fn write_response(stream: &mut TcpStream, response: Response, head: bool) -> io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        206 => "Partial Content",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    write!(stream, "HTTP/1.1 {} {}\r\n", response.status, reason)?;
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    if !head {
        write!(stream, "X-Datafs-Local: 1\r\n")?;
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        response.content_length.unwrap_or(response.body.len())
    )?;
    if !head {
        stream.write_all(&response.body)?;
    }
    Ok(())
}

fn proxy(stream: &mut TcpStream, request: &[u8], upstream: &str) -> io::Result<()> {
    let (method, target, headers) = request_parts(request)?;
    let mut remote = TcpStream::connect(upstream)?;
    write!(remote, "{method} {target} HTTP/1.1\r\n")?;
    for header in headers {
        let lower = header.to_ascii_lowercase();
        if !lower.starts_with("connection:") && !lower.starts_with("host:") {
            write!(remote, "{header}\r\n")?;
        }
    }
    write!(remote, "Host: {upstream}\r\nConnection: close\r\n\r\n")?;
    io::copy(&mut remote, stream)?;
    Ok(())
}

fn connection(mut stream: TcpStream, backend: &dyn FilesystemDispatch) -> io::Result<()> {
    loop {
        let request = read_request(&mut stream)?;
        if request.is_empty() {
            return Ok(());
        }
        let (method, target, headers) = request_parts(&request)?;
        if let Some(internal) = target.strip_prefix("/.__datafs/") {
            let (kind, path) = internal.split_once('/').unwrap_or((internal, ""));
            let response = backend.internal(kind, path, range(&headers));
            write_response(&mut stream, response, method == "HEAD")?;
        } else {
            proxy(&mut stream, &request, backend.upstream())?;
        }
    }
}

impl Server {
    pub fn start(backend: Arc<dyn FilesystemDispatch>) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        thread::Builder::new()
            .name("datafs-dispatch".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            let backend = Arc::clone(&backend);
                            let _ = thread::Builder::new()
                                .name("datafs-dispatch-client".into())
                                .spawn(move || {
                                    let _ = connection(stream, backend.as_ref());
                                });
                        }
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self { address })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}
