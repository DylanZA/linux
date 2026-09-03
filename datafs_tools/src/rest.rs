// SPDX-License-Identifier: GPL-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpStream;

use crate::dispatch::{FilesystemDispatch, Response};

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn byte(&mut self, byte: u8) -> Result<(), String> {
        self.whitespace();
        if self.bytes.get(self.pos) != Some(&byte) {
            return Err(format!("expected '{}' at byte {}", byte as char, self.pos));
        }
        self.pos += 1;
        Ok(())
    }

    fn string(&mut self) -> Result<String, String> {
        self.whitespace();
        self.byte(b'"')?;
        let mut value = String::new();
        while let Some(&byte) = self.bytes.get(self.pos) {
            self.pos += 1;
            match byte {
                b'"' => return Ok(value),
                b'\\' => {
                    let escaped = *self
                        .bytes
                        .get(self.pos)
                        .ok_or_else(|| "unterminated JSON escape".to_string())?;
                    self.pos += 1;
                    match escaped {
                        b'"' | b'\\' | b'/' => value.push(escaped as char),
                        b'b' => value.push('\u{8}'),
                        b'f' => value.push('\u{c}'),
                        b'n' => value.push('\n'),
                        b'r' => value.push('\r'),
                        b't' => value.push('\t'),
                        _ => return Err("unsupported Unicode escape in OAS path".into()),
                    }
                }
                0..=0x1f => return Err("control byte in JSON string".into()),
                _ => value.push(byte as char),
            }
        }
        Err("unterminated JSON string".into())
    }

    fn value_end(&mut self) -> Result<usize, String> {
        self.whitespace();
        let start = self.pos;
        match self.bytes.get(self.pos).copied() {
            Some(b'"') => {
                self.string()?;
            }
            Some(b'{') | Some(b'[') => {
                let open = self.bytes[self.pos];
                let close = if open == b'{' { b'}' } else { b']' };
                let mut depth = 0usize;
                let mut quoted = false;
                let mut escaped = false;
                while let Some(&byte) = self.bytes.get(self.pos) {
                    self.pos += 1;
                    if quoted {
                        if escaped {
                            escaped = false;
                        } else if byte == b'\\' {
                            escaped = true;
                        } else if byte == b'"' {
                            quoted = false;
                        }
                    } else if byte == b'"' {
                        quoted = true;
                    } else if byte == open {
                        depth += 1;
                    } else if byte == close {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(self.pos);
                        }
                    }
                }
                return Err("unterminated JSON container".into());
            }
            Some(_) => {
                while self.pos < self.bytes.len()
                    && !matches!(self.bytes[self.pos], b',' | b'}' | b']')
                {
                    self.pos += 1;
                }
            }
            None => return Err("expected JSON value".into()),
        }
        Ok(self.pos.max(start))
    }

    fn fields(&mut self) -> Result<Vec<(String, usize, usize)>, String> {
        self.byte(b'{')?;
        let mut result = Vec::new();
        loop {
            self.whitespace();
            if self.bytes.get(self.pos) == Some(&b'}') {
                self.pos += 1;
                return Ok(result);
            }
            let name = self.string()?;
            self.byte(b':')?;
            self.whitespace();
            let start = self.pos;
            let end = self.value_end()?;
            result.push((name, start, end));
            self.whitespace();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(result);
                }
                _ => return Err(format!("expected object separator at byte {}", self.pos)),
            }
        }
    }
}

fn fields(bytes: &[u8]) -> Result<Vec<(String, usize, usize)>, String> {
    Parser { bytes, pos: 0 }.fields()
}

fn response(status: u16, body: Vec<u8>) -> Response {
    Response {
        status,
        headers: Vec::new(),
        body,
        content_length: None,
    }
}

pub struct RestDispatch {
    upstream: String,
    base: String,
    schemas: BTreeMap<String, Vec<u8>>,
    directories: BTreeMap<String, Vec<u8>>,
    inodes: BTreeMap<String, u64>,
}

impl RestDispatch {
    fn fetch_document(upstream: &str, path: &str) -> Result<Vec<u8>, String> {
        let mut stream = TcpStream::connect(upstream).map_err(|error| error.to_string())?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
        )
        .map_err(|error| error.to_string())?;
        let mut reply = Vec::new();
        stream
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut reply)
            .map_err(|error| error.to_string())?;
        if reply.len() > 16 * 1024 * 1024 {
            return Err("response exceeds 16 MiB".into());
        }
        let header_end = reply
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| "response has no HTTP header terminator".to_string())?;
        let headers = std::str::from_utf8(&reply[..header_end])
            .map_err(|_| "response headers are not UTF-8".to_string())?;
        let status = headers.lines().next().unwrap_or_default();
        if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
            return Err(format!("server returned {}", status.trim()));
        }
        Ok(reply[header_end + 4..].to_vec())
    }

    pub fn discover(upstream: String, base: String) -> Result<(Self, String), String> {
        let base = base.trim_end_matches('/');
        let mut candidates = vec![
            "/openapi.json".to_string(),
            "/openapi.yaml".to_string(),
            "/swagger.json".to_string(),
            "/api/openapi.json".to_string(),
            "/v3/api-docs".to_string(),
        ];
        if !base.is_empty() {
            candidates.insert(0, format!("{base}/openapi.json"));
            candidates.insert(1, format!("{base}/swagger.json"));
        }
        candidates.dedup();
        let mut failures = Vec::new();
        for path in candidates {
            eprintln!("datafs REST: probing http://{upstream}{path}");
            let document = match Self::fetch_document(&upstream, &path) {
                Ok(document) => document,
                Err(error) => {
                    eprintln!("datafs REST: {path}: {error}");
                    failures.push(format!("{path}: {error}"));
                    continue;
                }
            };
            match Self::new(upstream.clone(), base.to_string(), &document) {
                Ok(dispatch) => return Ok((dispatch, path)),
                Err(error) => {
                    eprintln!("datafs REST: {path}: not a supported OpenAPI document: {error}");
                    failures.push(format!("{path}: {error}"));
                }
            }
        }
        Err(format!(
            "OpenAPI discovery failed:\n  {}",
            failures.join("\n  ")
        ))
    }

    pub fn new(upstream: String, base: String, document: &[u8]) -> Result<Self, String> {
        let root = fields(document)?;
        if !root.iter().any(|(name, _, _)| name == "openapi") {
            return Err("document has no top-level openapi field".into());
        }
        let (_, start, end) = root
            .iter()
            .find(|(name, _, _)| name == "paths")
            .ok_or_else(|| "document has no top-level paths object".to_string())?;
        let paths = &document[*start..*end];
        let mut schemas = BTreeMap::new();
        for (oas_path, start, end) in fields(paths)? {
            let path = oas_path.trim_matches('/');
            if path.is_empty() || oas_path.contains('?') {
                return Err(format!("invalid OAS path: {oas_path}"));
            }
            let item = &paths[start..end];
            if let Some((_, op_start, op_end)) = fields(item)?
                .into_iter()
                .find(|(method, _, _)| method.eq_ignore_ascii_case("get"))
            {
                let mut schema = item[op_start..op_end].to_vec();
                schema.push(b'\n');
                schemas.insert(path.to_string(), schema);
            }
        }
        if schemas.is_empty() {
            return Err("OAS document contains no GET operations".into());
        }

        let mut children = BTreeMap::<String, BTreeSet<String>>::new();
        children
            .entry(String::new())
            .or_default()
            .insert(".schema/".into());
        for path in schemas.keys() {
            for prefix in ["", ".schema/"] {
                let full = format!("{prefix}{path}");
                let parts: Vec<_> = full.split('/').collect();
                for index in 0..parts.len() {
                    let parent = parts[..index].join("/");
                    let child = if index + 1 < parts.len() {
                        format!("{}/", parts[index])
                    } else {
                        parts[index].to_string()
                    };
                    children.entry(parent).or_default().insert(child);
                }
            }
        }
        let directories = children
            .into_iter()
            .map(|(path, entries)| {
                let listing = entries.into_iter().collect::<Vec<_>>().join("\n") + "\n";
                (path, listing.into_bytes())
            })
            .collect::<BTreeMap<_, _>>();
        let mut inodes = BTreeMap::new();
        let mut next_ino = 2;
        for path in directories.keys().chain(schemas.keys()) {
            inodes.insert(path.clone(), next_ino);
            next_ino += 1;
        }
        for path in schemas.keys() {
            inodes.insert(format!(".schema/{path}"), next_ino);
            next_ino += 1;
        }
        Ok(Self {
            upstream,
            base,
            schemas,
            directories,
            inodes,
        })
    }

    fn remote_length(&self, path: &str) -> Result<usize, ()> {
        let mut stream = TcpStream::connect(&self.upstream).map_err(|_| ())?;
        write!(
            stream,
            "HEAD {}/{path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.base.trim_end_matches('/'),
            self.upstream
        )
        .map_err(|_| ())?;
        let mut reply = String::new();
        stream.read_to_string(&mut reply).map_err(|_| ())?;
        if !reply.starts_with("HTTP/1.1 200") && !reply.starts_with("HTTP/1.0 200") {
            return Err(());
        }
        reply
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .ok_or(())
    }

    fn metadata(&self, requested: &str) -> Response {
        let canonical = requested
            .split('?')
            .next()
            .unwrap_or(requested)
            .trim_matches('/');
        let (kind, size, inode_path) = if self.directories.contains_key(canonical) {
            (2, 0, canonical)
        } else if let Some(path) = canonical.strip_prefix(".schema/") {
            match self.schemas.get(path) {
                Some(schema) => (3, schema.len(), canonical),
                None => return response(404, Vec::new()),
            }
        } else if self.schemas.contains_key(canonical) {
            match self.remote_length(requested) {
                Ok(size) => (1, size, canonical),
                Err(()) => return response(404, Vec::new()),
            }
        } else {
            return response(404, Vec::new());
        };
        let mut result = response(200, Vec::new());
        result.content_length = Some(size);
        result
            .headers
            .push(("X-Datafs-Kind".into(), kind.to_string()));
        result.headers.push((
            "X-Datafs-Ino".into(),
            self.inodes
                .get(inode_path)
                .copied()
                .unwrap_or(1)
                .to_string(),
        ));
        result
    }

    fn ranged(body: &[u8], range: Option<(usize, usize)>) -> Response {
        let Some((start, end)) = range else {
            return response(200, body.to_vec());
        };
        if start >= body.len() || end < start {
            return response(404, Vec::new());
        }
        response(206, body[start..=end.min(body.len() - 1)].to_vec())
    }
}

impl FilesystemDispatch for RestDispatch {
    fn internal(&self, kind: &str, path: &str, range: Option<(usize, usize)>) -> Response {
        match kind {
            "meta" => self.metadata(path),
            "dir" => self
                .directories
                .get(path.split('?').next().unwrap_or(path).trim_matches('/'))
                .map_or_else(
                    || response(404, Vec::new()),
                    |body| response(200, body.clone()),
                ),
            "schema" => {
                let canonical = path
                    .split('?')
                    .next()
                    .unwrap_or(path)
                    .trim_matches('/')
                    .strip_prefix(".schema/")
                    .unwrap_or_default();
                self.schemas.get(canonical).map_or_else(
                    || response(404, Vec::new()),
                    |body| Self::ranged(body, range),
                )
            }
            _ => response(404, Vec::new()),
        }
    }

    fn upstream(&self) -> &str {
        &self.upstream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatches_tree_and_schema_without_bpf_nodes() {
        let spec = br#"{
            "openapi":"3.1.0",
            "paths":{"/api/foo":{"get":{"parameters":[{"name":"a"}]}}}
        }"#;
        let backend = RestDispatch::new("127.0.0.1:9".into(), "/v1".into(), spec).unwrap();
        assert_eq!(backend.internal("dir", "api", None).body, b"foo\n");
        let schema = backend.internal("schema", ".schema/api/foo", Some((0, 3)));
        assert_eq!(schema.status, 206);
        assert_eq!(schema.body, b"{\"pa");
    }

    #[test]
    fn accepts_bundled_arithmetic_openapi_document() {
        let spec = include_bytes!("../datafs_rest_example.openapi.json");
        let backend = RestDispatch::new("127.0.0.1:9".into(), "/v1".into(), spec).unwrap();
        let root = backend.internal("dir", "", None).body;
        assert!(root.windows(4).any(|entry| entry == b"add\n"));
        assert!(root.windows(7).any(|entry| entry == b"divide\n"));
        assert_eq!(backend.internal("meta", "missing", None).status, 404);
    }
}
