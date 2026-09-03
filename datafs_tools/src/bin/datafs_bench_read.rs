// SPDX-License-Identifier: GPL-2.0

use std::env;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::ptr::NonNull;
use std::time::Instant;

use datafs_tools::parse_u64;

const DEFAULT_LEN: u64 = 4096;
const DEFAULT_ITERS: u32 = 100;
const DEFAULT_WARMUP: u32 = 5;
const DEFAULT_ALIGN: usize = 4096;

struct Options {
    path: Option<OsString>,
    length: u64,
    offset: u64,
    iterations: u32,
    warmup: u32,
    alignment: usize,
    direct: bool,
    csv: bool,
    label: String,
}

struct Aligned {
    ptr: NonNull<u8>,
    len: usize,
}
impl Aligned {
    fn new(len: usize, alignment: usize) -> io::Result<Self> {
        let mut ptr = std::ptr::null_mut();
        let ret = unsafe { libc::posix_memalign(&mut ptr, alignment, len) };
        if ret != 0 {
            return Err(io::Error::from_raw_os_error(ret));
        }
        unsafe {
            ptr.cast::<u8>().write_bytes(0, len);
        }
        Ok(Self {
            ptr: NonNull::new(ptr.cast()).unwrap(),
            len,
        })
    }
}
impl Drop for Aligned {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.ptr.as_ptr().cast());
        }
    }
}

fn usage() {
    eprintln!(
        "usage: datafs_bench_read -p path [-m pread] [-l len] [-o offset] [-i iters] [-w warmup] [-a align] [-L label] [-d] [-c]"
    );
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
    let mut options = Options {
        path: None,
        length: DEFAULT_LEN,
        offset: 0,
        iterations: DEFAULT_ITERS,
        warmup: DEFAULT_WARMUP,
        alignment: DEFAULT_ALIGN,
        direct: false,
        csv: false,
        label: String::new(),
    };
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-p") => options.path = Some(value(&mut args, "-p")?),
            Some("-m") => {
                if value(&mut args, "-m")?.to_str() != Some("pread") {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid mode"));
                }
            }
            Some("-l") => options.length = parse_u64(&value(&mut args, "-l")?, "length")?,
            Some("-o") => options.offset = parse_u64(&value(&mut args, "-o")?, "offset")?,
            Some("-i") => {
                options.iterations =
                    u32::try_from(parse_u64(&value(&mut args, "-i")?, "iterations")?).map_err(
                        |_| io::Error::new(io::ErrorKind::InvalidInput, "iterations overflow"),
                    )?
            }
            Some("-w") => {
                options.warmup = u32::try_from(parse_u64(&value(&mut args, "-w")?, "warmup")?)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "warmup overflow"))?
            }
            Some("-a") => {
                options.alignment =
                    usize::try_from(parse_u64(&value(&mut args, "-a")?, "alignment")?).map_err(
                        |_| io::Error::new(io::ErrorKind::InvalidInput, "alignment overflow"),
                    )?
            }
            Some("-L") => options.label = value(&mut args, "-L")?.to_string_lossy().into_owned(),
            Some("-d") => options.direct = true,
            Some("-c") => options.csv = true,
            Some("-h") => {
                usage();
                std::process::exit(0);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown option",
                ));
            }
        }
    }
    if options.path.is_none()
        || options.length == 0
        || options.length > u32::MAX as u64
        || options.iterations == 0
        || options.alignment == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid benchmark arguments",
        ));
    }
    Ok(options)
}

fn one(options: &Options, fd: i32, buffer: &Aligned) -> io::Result<usize> {
    let ret = unsafe {
        libc::pread(
            fd,
            buffer.ptr.as_ptr().cast(),
            buffer.len,
            options.offset as libc::off_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

fn percentile(samples: &[f64], percentage: usize) -> f64 {
    let index = (samples.len() * percentage)
        .div_ceil(100)
        .clamp(1, samples.len());
    samples[index - 1]
}

fn run() -> io::Result<()> {
    let options = parse()?;
    let mut open = OpenOptions::new();
    open.read(true);
    if options.direct {
        open.custom_flags(libc::O_DIRECT);
    }
    let file = open.open(options.path.as_ref().unwrap())?;
    let buffer = Aligned::new(options.length as usize, options.alignment)?;
    for _ in 0..options.warmup {
        let bytes = one(&options, file.as_raw_fd(), &buffer)?;
        if bytes != options.length as usize {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
    }
    let mut samples = Vec::with_capacity(options.iterations as usize);
    let mut bytes = 0u64;
    for _ in 0..options.iterations {
        let start = Instant::now();
        let read = one(&options, file.as_raw_fd(), &buffer)?;
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        if read != options.length as usize {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        samples.push(elapsed);
        bytes += read as u64;
    }
    samples.sort_by(f64::total_cmp);
    let total: f64 = samples.iter().sum();
    let mean = total / samples.len() as f64;
    let throughput = bytes as f64 / (1024.0 * 1024.0) / (total / 1000.0);
    let mode = "pread";
    let path = options.path.as_ref().unwrap().to_string_lossy();
    if options.csv {
        println!(
            "label,path,mode,direct,len,offset,iters,warmup,bytes,total_ms,min_ms,mean_ms,p50_ms,p90_ms,p99_ms,max_ms,mib_s"
        );
        println!(
            "{},{path},{mode},{},{},{},{},{},{bytes},{total:.3},{:.3},{mean:.3},{:.3},{:.3},{:.3},{:.3},{throughput:.3}",
            options.label,
            options.direct as u8,
            options.length,
            options.offset,
            options.iterations,
            options.warmup,
            samples[0],
            percentile(&samples, 50),
            percentile(&samples, 90),
            percentile(&samples, 99),
            samples[samples.len() - 1]
        );
    } else {
        println!(
            "label={} path={path} mode={mode} direct={} len={} offset={} iters={} warmup={}",
            options.label,
            options.direct as u8,
            options.length,
            options.offset,
            options.iterations,
            options.warmup
        );
        println!("bytes={bytes} total_ms={total:.3} mib_s={throughput:.3}");
        println!(
            "lat_ms min={:.3} mean={mean:.3} p50={:.3} p90={:.3} p99={:.3} max={:.3}",
            samples[0],
            percentile(&samples, 50),
            percentile(&samples, 90),
            percentile(&samples, 99),
            samples[samples.len() - 1]
        );
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        usage();
        eprintln!("benchmark: {error}");
        std::process::exit(1);
    }
}
