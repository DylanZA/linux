// SPDX-License-Identifier: GPL-2.0

use std::env;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

use datafs_tools::{devmem::Devmem, parse_u64};

struct Options {
    path: OsString,
    expected: Option<OsString>,
    length: u32,
    offset: u64,
    iface: String,
    rxq: u32,
    require_devmem: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("datafs_devmem_smoke: {error}");
        std::process::exit(1);
    }
}

fn value(args: &mut impl Iterator<Item = OsString>, option: &str) -> io::Result<OsString> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{option} requires a value"),
        )
    })
}

fn parse() -> io::Result<Options> {
    let mut path = None;
    let mut expected = None;
    let mut length = 4096u64;
    let mut offset = 0;
    let mut iface = None;
    let mut rxq = None;
    let mut require_devmem = false;
    let mut args = env::args_os().skip(1);

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-p" | "--path") => path = Some(value(&mut args, "--path")?),
            Some("-e" | "--expected") => expected = Some(value(&mut args, "--expected")?),
            Some("-l" | "--length") => {
                length = parse_u64(&value(&mut args, "--length")?, "length")?
            }
            Some("-o" | "--offset") => {
                offset = parse_u64(&value(&mut args, "--offset")?, "offset")?
            }
            Some("-i" | "--iface") => {
                iface = Some(value(&mut args, "--iface")?.into_string().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid interface")
                })?)
            }
            Some("-q" | "--rxq") => rxq = Some(parse_u64(&value(&mut args, "--rxq")?, "rxq")?),
            Some("--require-devmem") => require_devmem = true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "usage: datafs_devmem_smoke --path PATH [--expected PATH] [--length LEN] [--offset OFFSET] --iface IFACE --rxq QUEUE [--require-devmem]",
                ));
            }
        }
    }

    let length = u32::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length must fit u32"))?;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "length must be nonzero",
        ));
    }
    Ok(Options {
        path: path
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--path is required"))?,
        expected,
        length,
        offset,
        iface: iface
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--iface is required"))?,
        rxq: u32::try_from(
            rxq.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--rxq is required"))?,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "rxq must fit u32"))?,
        require_devmem,
    })
}

fn run() -> io::Result<()> {
    let options = parse()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(&options.path)?;
    let mut output = vec![0u8; options.length as usize];
    let mut devmem = Devmem::new(&options.iface, options.rxq)?;
    let (total, stats) = devmem.read(file.as_raw_fd(), &mut output, options.offset)?;
    if options.require_devmem && stats.dmabuf == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "read completed without dma-buf extents",
        ));
    }
    println!(
        "datafs devmem binding={} ring_flags=0x{:x} fragments={} host={} dmabuf={} host_bytes={} dmabuf_bytes={} tokens={}",
        devmem.binding_id(),
        devmem.setup_flags(),
        stats.fragments,
        stats.host,
        stats.dmabuf,
        stats.host_bytes,
        stats.dmabuf_bytes,
        stats.tokens
    );

    if let Some(expected_path) = options.expected {
        let mut expected_file = std::fs::File::open(expected_path)?;
        expected_file.seek(SeekFrom::Start(options.offset))?;
        let mut expected = Vec::new();
        expected_file
            .take(options.length.into())
            .read_to_end(&mut expected)?;
        if total != expected.len() || output[..total] != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datafs devmem output differs from reference data",
            ));
        }
        println!("comparison ok ({total} bytes)");
    }
    println!("completion ok ({total} bytes)");
    Ok(())
}
