// SPDX-License-Identifier: GPL-2.0

use std::env;
use std::ffi::{CStr, CString, OsStr, OsString, c_char, c_int, c_long, c_void};
use std::io;
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

use crate::parse_u64;

const FSOPEN_CLOEXEC: u32 = 1;
const FSMOUNT_CLOEXEC: u32 = 1;
const FSCONFIG_SET_STRING: u32 = 1;
const FSCONFIG_CMD_CREATE: u32 = 6;
const MOVE_MOUNT_F_EMPTY_PATH: u32 = 4;
const MOUNT_ATTR_RDONLY: u32 = 1;
const MNT_DETACH: c_int = 2;
const MAX_LOAN_SOCKETS: u32 = 1024;

#[repr(C)]
struct BpfObject(c_void);
#[repr(C)]
struct BpfMap(c_void);
#[repr(C)]
struct BpfLink(c_void);

unsafe extern "C" {
    fn bpf_object__open_file(path: *const c_char, opts: *const c_void) -> *mut BpfObject;
    fn bpf_object__load(object: *mut BpfObject) -> c_int;
    fn bpf_object__find_map_by_name(object: *const BpfObject, name: *const c_char) -> *mut BpfMap;
    fn bpf_map__fd(map: *const BpfMap) -> c_int;
    fn bpf_map__attach_struct_ops(map: *const BpfMap) -> *mut BpfLink;
    fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
    fn bpf_object__close(object: *mut BpfObject);
    fn libbpf_get_error(ptr: *const c_void) -> c_long;
}

fn c_ptr(value: &CStr) -> *const c_char {
    value.to_bytes_with_nul().as_ptr().cast()
}

struct Bpf {
    object: *mut BpfObject,
    link: *mut BpfLink,
}

impl Bpf {
    fn load(path: &Path, map_name: &CStr) -> io::Result<Self> {
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "BPF path contains NUL"))?;
        // SAFETY: libbpf retains its own state and all C strings outlive each call.
        unsafe {
            let object = bpf_object__open_file(c_ptr(&path_c), ptr::null());
            if object.is_null() {
                return Err(io::Error::last_os_error());
            }
            let ret = bpf_object__load(object);
            if ret != 0 {
                bpf_object__close(object);
                return Err(io::Error::from_raw_os_error(-ret));
            }
            let map = bpf_object__find_map_by_name(object, c_ptr(map_name));
            if map.is_null() {
                bpf_object__close(object);
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "struct_ops map not found",
                ));
            }
            let link = bpf_map__attach_struct_ops(map);
            let error = libbpf_get_error(link.cast());
            if error != 0 {
                bpf_object__close(object);
                return Err(io::Error::from_raw_os_error((-error) as i32));
            }
            Ok(Self { object, link })
        }
    }

    fn map_fd(&self, name: &CStr) -> io::Result<c_int> {
        // SAFETY: the BPF object owns the map and remains loaded for this call.
        unsafe {
            let map = bpf_object__find_map_by_name(self.object, c_ptr(name));
            if map.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("BPF map {} not found", name.to_string_lossy()),
                ));
            }
            let fd = bpf_map__fd(map);
            if fd < 0 {
                return Err(io::Error::from_raw_os_error(-fd));
            }
            Ok(fd)
        }
    }
}

impl Drop for Bpf {
    fn drop(&mut self) {
        // SAFETY: these pointers are uniquely owned by this value.
        unsafe {
            bpf_link__destroy(self.link);
            bpf_object__close(self.object);
        }
    }
}

#[derive(Clone, Copy)]
struct SocketPoolMaps {
    sockets: &'static CStr,
    available: &'static CStr,
}

#[derive(Default)]
struct MountOptions {
    path: Option<OsString>,
    server: Option<OsString>,
    argument: Option<OsString>,
    loan_sockets: u32,
    timeout_ms: u32,
    buf_size: u32,
    pool_size: u32,
}

fn usage(program: &OsStr, socket_pool: bool) {
    let pool_usage = if socket_pool {
        "\n--loan-sockets N      sockets to loan to datafs (max: 1024)"
    } else {
        ""
    };
    eprintln!(
        "usage: {} [options] [bpf-object] [struct-ops-map]\n\
         \n\
           --mount PATH          mount datafs\n\
           --server HOST:PORT    server used with --mount\n\
           --arg VALUE           protocol mount argument (bucket/export/share)\n\
           --timeout-ms N        datafs timeout (default: 5000)\n\
           --buf-size N          callback buffer (default: 4096)\n\
           --pool-size N         connection pool size (default: 8){}",
        program.to_string_lossy(),
        pool_usage,
    );
}

fn take_value(args: &mut impl Iterator<Item = OsString>, option: &str) -> Result<OsString, String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_nonzero(value: OsString, option: &str) -> Result<u32, String> {
    let parsed = u32::try_from(parse_u64(&value, option).map_err(|_| format!("invalid {option}"))?)
        .map_err(|_| format!("invalid {option}"))?;
    if parsed == 0 {
        Err(format!("{option} must be nonzero"))
    } else {
        Ok(parsed)
    }
}

fn parse_loan_sockets(value: OsString) -> Result<u32, String> {
    let count = parse_nonzero(value, "--loan-sockets")?;

    if count > MAX_LOAN_SOCKETS {
        Err(format!("--loan-sockets must not exceed {MAX_LOAN_SOCKETS}"))
    } else {
        Ok(count)
    }
}

fn cstring(value: &OsStr, what: &str) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{what} contains NUL")))
}

fn fsconfig_string(fd: c_int, key: &CStr, value: &OsStr) -> io::Result<()> {
    let value = cstring(value, "mount option")?;
    // SAFETY: pointers are valid for this syscall and fd is an fs context.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fd,
            FSCONFIG_SET_STRING,
            c_ptr(key),
            c_ptr(&value),
            0,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn mount_filesystem(options: &MountOptions, ops_name: &CStr) -> io::Result<()> {
    // SAFETY: the filesystem name is a valid C string.
    let fd = unsafe { libc::syscall(libc::SYS_fsopen, c_ptr(c"datafs"), FSOPEN_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: syscall returned ownership of this descriptor.
    let fsfd = unsafe { OwnedFd::from_raw_fd(fd as c_int) };
    fsconfig_string(
        fsfd.as_raw_fd(),
        c"servers",
        options.server.as_ref().unwrap(),
    )?;
    fsconfig_string(
        fsfd.as_raw_fd(),
        c"ops",
        OsStr::from_bytes(ops_name.to_bytes()),
    )?;
    fsconfig_string(fsfd.as_raw_fd(), c"arg", options.argument.as_ref().unwrap())?;
    fsconfig_string(
        fsfd.as_raw_fd(),
        c"timeout_ms",
        OsStr::new(&options.timeout_ms.to_string()),
    )?;
    fsconfig_string(
        fsfd.as_raw_fd(),
        c"buf_size",
        OsStr::new(&options.buf_size.to_string()),
    )?;
    fsconfig_string(
        fsfd.as_raw_fd(),
        c"pool_size",
        OsStr::new(&options.pool_size.to_string()),
    )?;
    // SAFETY: no pointer arguments are used by FSCONFIG_CMD_CREATE.
    if unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fsfd.as_raw_fd(),
            FSCONFIG_CMD_CREATE,
            ptr::null::<c_void>(),
            ptr::null::<c_void>(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fsfd is a configured filesystem context.
    let mount_fd = unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            fsfd.as_raw_fd(),
            FSMOUNT_CLOEXEC,
            MOUNT_ATTR_RDONLY,
        )
    };
    if mount_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: syscall returned ownership of this descriptor.
    let mount_fd = unsafe { OwnedFd::from_raw_fd(mount_fd as c_int) };
    let path = Path::new(options.path.as_ref().unwrap());
    std::fs::create_dir_all(path)?;
    let path_c = cstring(path.as_os_str(), "mount path")?;
    // SAFETY: both descriptors and path pointers are valid.
    if unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount_fd.as_raw_fd(),
            c_ptr(c""),
            libc::AT_FDCWD,
            c_ptr(&path_c),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn map_update_error(ret: c_int) -> io::Error {
    io::Error::from_raw_os_error(-ret)
}

fn setup_socket_pool(
    bpf: &Bpf,
    maps: SocketPoolMaps,
    server: &OsStr,
    count: u32,
) -> io::Result<Vec<TcpStream>> {
    let server = server
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "server is not valid UTF-8"))?;
    let mut streams = Vec::with_capacity(count as usize);

    for key in 0..count {
        let stream = TcpStream::connect(server).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to connect loan socket {key} to {server}: {error}"),
            )
        })?;
        streams.push(stream);
    }

    let sockets_fd = bpf.map_fd(maps.sockets)?;
    let available_fd = bpf.map_fd(maps.available)?;
    for (key, stream) in streams.iter().enumerate() {
        let key = key as u32;
        let socket_fd = stream.as_raw_fd() as u64;
        // SAFETY: the map FDs are valid and the key/value pointers match their map ABI.
        let ret = unsafe {
            bpf_map_update_elem(
                sockets_fd,
                ptr::from_ref(&key).cast(),
                ptr::from_ref(&socket_fd).cast(),
                0,
            )
        };
        if ret != 0 {
            return Err(io::Error::new(
                map_update_error(ret).kind(),
                format!(
                    "failed to install loan socket {key}: {}",
                    map_update_error(ret)
                ),
            ));
        }
    }
    for key in 0..count {
        // SAFETY: queue maps require a NULL key and the value is a u32 map element.
        let ret = unsafe {
            bpf_map_update_elem(available_fd, ptr::null(), ptr::from_ref(&key).cast(), 0)
        };
        if ret != 0 {
            return Err(io::Error::new(
                map_update_error(ret).kind(),
                format!(
                    "failed to seed loan socket key {key}: {}",
                    map_update_error(ret)
                ),
            ));
        }
    }

    Ok(streams)
}

fn default_object(program: &OsStr, object: &str) -> PathBuf {
    let path = Path::new(program);
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join(object)
}

fn block_termination_signals() -> io::Result<libc::sigset_t> {
    let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: set points to initialized process-local storage.
    unsafe {
        if libc::sigemptyset(&mut set) != 0
            || libc::sigaddset(&mut set, libc::SIGINT) != 0
            || libc::sigaddset(&mut set, libc::SIGTERM) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let ret = libc::pthread_sigmask(libc::SIG_BLOCK, &set, ptr::null_mut());
        if ret != 0 {
            return Err(io::Error::from_raw_os_error(ret));
        }
    }
    Ok(set)
}

pub fn run(default_object_name: &str, default_map_name: &str) -> i32 {
    run_inner(default_object_name, default_map_name, None, false)
}

pub fn run_s3(default_object_name: &str, default_map_name: &str) -> i32 {
    run_inner(
        default_object_name,
        default_map_name,
        Some(SocketPoolMaps {
            sockets: c"datafs_s3_sock",
            available: c"datafs_s3_avail",
        }),
        false,
    )
}

pub fn run_rest() -> i32 {
    run_inner("datafs_rest.bpf.o", "datafs_rest", None, true)
}

fn run_inner(
    default_object_name: &str,
    default_map_name: &str,
    socket_pool_maps: Option<SocketPoolMaps>,
    rest: bool,
) -> i32 {
    let mut args = env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| OsString::from("datafs_loader"));
    let mut options = MountOptions {
        timeout_ms: 5000,
        buf_size: 4096,
        pool_size: 8,
        ..Default::default()
    };
    let mut positional = Vec::new();
    let mut parse_error = None;

    while let Some(arg) = args.next() {
        let result = match arg.to_str() {
            Some("--mount") => take_value(&mut args, "--mount").map(|v| options.path = Some(v)),
            Some("--server") => take_value(&mut args, "--server").map(|v| options.server = Some(v)),
            Some("--arg") => take_value(&mut args, "--arg").map(|v| options.argument = Some(v)),
            Some("--loan-sockets") if socket_pool_maps.is_some() => {
                take_value(&mut args, "--loan-sockets")
                    .and_then(parse_loan_sockets)
                    .map(|v| options.loan_sockets = v)
            }
            Some("--timeout-ms") => take_value(&mut args, "--timeout-ms")
                .and_then(|v| parse_nonzero(v, "--timeout-ms"))
                .map(|v| options.timeout_ms = v),
            Some("--buf-size") => take_value(&mut args, "--buf-size")
                .and_then(|v| parse_nonzero(v, "--buf-size"))
                .map(|v| options.buf_size = v),
            Some("--pool-size") => take_value(&mut args, "--pool-size")
                .and_then(|v| parse_nonzero(v, "--pool-size"))
                .map(|v| options.pool_size = v),
            Some("-h" | "--help") => {
                usage(&program, socket_pool_maps.is_some());
                return 0;
            }
            Some(value) if value.starts_with('-') => Err(format!("unknown option {value}")),
            _ => {
                positional.push(arg);
                Ok(())
            }
        };
        if let Err(error) = result {
            parse_error = Some(error);
            break;
        }
    }
    if positional.len() > 2 {
        parse_error = Some("too many positional arguments".into());
    }
    if options.path.is_some() && (options.server.is_none() || options.argument.is_none()) {
        parse_error = Some("--mount requires --server and --arg".into());
    }
    if options.loan_sockets != 0 && options.path.is_none() {
        parse_error = Some("--loan-sockets requires --mount".into());
    }
    if rest && (options.server.is_none() || options.argument.is_none()) {
        parse_error = Some("REST dispatch requires --server and --arg".into());
    }
    if let Some(error) = parse_error {
        eprintln!("{error}");
        usage(&program, socket_pool_maps.is_some());
        return 2;
    }

    let object_path = positional
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_object(&program, default_object_name));
    let map_name = positional
        .get(1)
        .and_then(|v| v.to_str())
        .unwrap_or(default_map_name);
    let map_name_c = match CString::new(map_name) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("invalid map name");
            return 2;
        }
    };

    let termination_signals = match block_termination_signals() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed to block termination signals: {error}");
            return 1;
        }
    };

    let _ = Command::new("modprobe").arg("datafs").status();
    // SAFETY: rlimit is fully initialized.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) != 0 {
            eprintln!(
                "warning: failed to raise RLIMIT_MEMLOCK: {}",
                io::Error::last_os_error()
            );
        }
    }

    let bpf = match Bpf::load(&object_path, &map_name_c) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed to attach struct_ops {map_name}: {error}");
            return 1;
        }
    };
    let _dispatch_server = if rest {
        let (backend, discovered_path) = match crate::rest::RestDispatch::discover(
            options
                .server
                .as_ref()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            options
                .argument
                .as_ref()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("invalid OpenAPI document: {error}");
                return 1;
            }
        };
        let server = match crate::dispatch::Server::start(std::sync::Arc::new(backend)) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("failed to start REST dispatch service: {error}");
                return 1;
            }
        };
        options.server = Some(server.address().to_string().into());
        println!("using OpenAPI document discovered at {discovered_path}");
        Some(server)
    } else {
        None
    };
    let loan_sockets = if options.loan_sockets != 0 {
        match setup_socket_pool(
            &bpf,
            socket_pool_maps.unwrap(),
            options.server.as_ref().unwrap(),
            options.loan_sockets,
        ) {
            Ok(streams) => streams,
            Err(error) => {
                eprintln!("failed to set up loan socket pool: {error}");
                return 1;
            }
        }
    } else {
        Vec::new()
    };
    let mounted = if let Some(path) = &options.path {
        if let Err(error) = mount_filesystem(&options, &map_name_c) {
            eprintln!("failed to mount {}: {error}", Path::new(path).display());
            return 1;
        }
        true
    } else {
        false
    };

    println!("attached {map_name} from {}", object_path.display());
    if mounted {
        println!(
            "mounted datafs at {}",
            Path::new(options.path.as_ref().unwrap()).display()
        );
    }
    if !loan_sockets.is_empty() {
        println!("initialized {} loan sockets", loan_sockets.len());
    }
    println!("keep this process running while datafs is mounted");

    let mut signal = 0;
    // SAFETY: the signals in this set have remained blocked since startup.
    let ret = unsafe { libc::sigwait(&termination_signals, &mut signal) };
    if ret != 0 {
        eprintln!(
            "warning: failed while waiting for termination: {}",
            io::Error::from_raw_os_error(ret)
        );
    }
    if mounted {
        let path = cstring(options.path.as_ref().unwrap(), "mount path").unwrap();
        // SAFETY: path is a valid mount path.
        if unsafe { libc::umount2(c_ptr(&path), MNT_DETACH) } != 0 {
            eprintln!(
                "warning: failed to unmount {}: {}",
                Path::new(options.path.as_ref().unwrap()).display(),
                io::Error::last_os_error()
            );
        }
    }
    0
}
