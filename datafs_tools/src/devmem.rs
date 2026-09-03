// SPDX-License-Identifier: GPL-2.0

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering, fence};

const HOST_BGID: u16 = 19;
const HOST_ENTRIES: u16 = 256;
const DMABUF_PAGES: usize = 16_000;
const READ_DATA: u64 = 0x6461_7461_6465_766d;
const DONTNEED_DATA: u64 = 0x6461_7461_6672_6565;
const COPY_DATA: u64 = 0x6461_7461_636f_7079;

const IORING_SETUP_CQSIZE: u32 = 1 << 3;
const IORING_SETUP_CQE32: u32 = 1 << 11;
const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
const IORING_OP_URING_CMD: u8 = 46;
const IORING_CQE_F_BUFFER: u32 = 1 << 0;
const IORING_CQE_F_MORE: u32 = 1 << 1;
const IORING_CQE_BUFFER_SHIFT: u32 = 16;
const IORING_URING_CMD_FIXED: u32 = 1 << 0;

const DATAFS_URING_CMD_RECV_DEVMEM: u32 = 1;
const DATAFS_URING_CMD_COPY_RESPONSE: u32 = 2;
const DATAFS_URING_F_WAIT_SOCKET: u32 = 1 << 0;
const DATAFS_URING_F_DEVMEM_DONTNEED: u32 = 1 << 1;
const DATAFS_DEVMEM_CQE_LOAN_SHIFT: u32 = 16;
const DATAFS_DEVMEM_CQE_F_COPY_REQUEST: u32 = 1 << 14;

const NETLINK_GENERIC: i32 = 16;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NETDEV_FAMILY_VERSION: u8 = 1;
const NETDEV_CMD_BIND_RX: u8 = 13;
const NETDEV_A_DMABUF_IFINDEX: u16 = 1;
const NETDEV_A_DMABUF_QUEUES: u16 = 2;
const NETDEV_A_DMABUF_FD: u16 = 3;
const NETDEV_A_DMABUF_ID: u16 = 4;
const NETDEV_A_QUEUE_ID: u16 = 1;
const NETDEV_A_QUEUE_TYPE: u16 = 3;
const NETDEV_QUEUE_TYPE_RX: u32 = 0;

const NLM_F_REQUEST: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(3 << 14);

const DMA_BUF_SYNC_READ: u64 = 1;
const DMA_BUF_SYNC_END: u64 = 1 << 2;
const UDMABUF_FLAGS_CLOEXEC: u32 = 1;

#[repr(C)]
#[derive(Default)]
struct SqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct CqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqOffsets,
    cq_off: CqOffsets,
}

#[repr(C)]
struct IoUringSq {
    khead: *mut u32,
    ktail: *mut u32,
    kring_mask: *mut u32,
    kring_entries: *mut u32,
    kflags: *mut u32,
    kdropped: *mut u32,
    array: *mut u32,
    sqes: *mut Sqe,
    sqe_head: u32,
    sqe_tail: u32,
    ring_sz: usize,
    ring_ptr: *mut libc::c_void,
    ring_mask: u32,
    ring_entries: u32,
    sqes_sz: u32,
    pad: u32,
}

#[repr(C)]
struct IoUringCq {
    khead: *mut u32,
    ktail: *mut u32,
    kring_mask: *mut u32,
    kring_entries: *mut u32,
    kflags: *mut u32,
    koverflow: *mut u32,
    cqes: *mut Cqe,
    ring_sz: usize,
    ring_ptr: *mut libc::c_void,
    ring_mask: u32,
    ring_entries: u32,
    pad: [u32; 2],
}

#[repr(C)]
struct IoUring {
    sq: IoUringSq,
    cq: IoUringCq,
    flags: u32,
    ring_fd: i32,
    features: u32,
    enter_ring_fd: i32,
    int_flags: u8,
    pad: [u8; 3],
    pad2: u32,
}

#[repr(C, align(8))]
struct Sqe {
    bytes: [u8; 64],
}

#[repr(C)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DatafsCqe {
    frag_offset: u64,
    frag_token: u32,
    dmabuf_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DatafsCopyCqe {
    key: u64,
    frag_offset: u64,
}

#[repr(C)]
struct Buf {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16,
}

#[repr(C)]
struct BufRing {
    resv1: u64,
    resv2: u32,
    resv3: u16,
    tail: AtomicU16,
}

#[repr(C)]
struct UdmabufCreate {
    memfd: u32,
    flags: u32,
    offset: u64,
    size: u64,
}

#[repr(C)]
struct DmaBufSync {
    flags: u64,
}

unsafe extern "C" {
    fn io_uring_queue_init_params(
        entries: u32,
        ring: *mut IoUring,
        params: *mut IoUringParams,
    ) -> i32;
    fn io_uring_queue_exit(ring: *mut IoUring);
    fn io_uring_setup_buf_ring(
        ring: *mut IoUring,
        entries: u32,
        bgid: i32,
        flags: u32,
        error: *mut i32,
    ) -> *mut BufRing;
    fn io_uring_free_buf_ring(
        ring: *mut IoUring,
        buffer_ring: *mut BufRing,
        entries: u32,
        bgid: i32,
    ) -> i32;
    fn io_uring_register_buffers(
        ring: *mut IoUring,
        iovecs: *const libc::iovec,
        nr_iovecs: u32,
    ) -> i32;
    fn io_uring_unregister_buffers(ring: *mut IoUring) -> i32;
    fn io_uring_submit(ring: *mut IoUring) -> i32;
    fn __io_uring_get_cqe(
        ring: *mut IoUring,
        cqe: *mut *mut Cqe,
        submit: u32,
        wait: u32,
        mask: *const libc::sigset_t,
    ) -> i32;
}

#[derive(Default)]
pub struct Stats {
    pub fragments: u32,
    pub host: u32,
    pub dmabuf: u32,
    pub host_bytes: u64,
    pub dmabuf_bytes: u64,
    pub tokens: u32,
}

struct Udmabuf {
    map: *mut u8,
    len: usize,
    fd: OwnedFd,
    _memfd: OwnedFd,
    _device: OwnedFd,
}

impl Udmabuf {
    fn new(page_size: usize) -> io::Result<Self> {
        let len = DMABUF_PAGES
            .checked_mul(page_size)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let device: OwnedFd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/udmabuf")?
            .into();
        let name = c"datafs-devmem-smoke";
        let memfd_raw = unsafe {
            libc::memfd_create(
                name.to_bytes_with_nul().as_ptr().cast(),
                libc::MFD_ALLOW_SEALING,
            )
        };
        if memfd_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let memfd = unsafe { OwnedFd::from_raw_fd(memfd_raw) };
        if unsafe { libc::fcntl(memfd.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_SHRINK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let length =
            i64::try_from(len).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        if unsafe { libc::ftruncate(memfd.as_raw_fd(), length) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let create = UdmabufCreate {
            memfd: u32::try_from(memfd.as_raw_fd())
                .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?,
            flags: UDMABUF_FLAGS_CLOEXEC,
            offset: 0,
            size: len as u64,
        };
        let fd_raw = unsafe {
            libc::ioctl(
                device.as_raw_fd(),
                iow(b'u', 0x42, mem::size_of::<UdmabufCreate>()),
                &create,
            )
        };
        if fd_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd_raw) };
        let map = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            map: map.cast(),
            len,
            fd,
            _memfd: memfd,
            _device: device,
        })
    }

    fn copy_to(&self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
        let offset =
            usize::try_from(offset).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        if offset > self.len || destination.len() > self.len - offset {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        self.sync(DMA_BUF_SYNC_READ)?;
        destination.copy_from_slice(unsafe {
            std::slice::from_raw_parts(self.map.add(offset), destination.len())
        });
        self.sync(DMA_BUF_SYNC_READ | DMA_BUF_SYNC_END)
    }

    fn sync(&self, flags: u64) -> io::Result<()> {
        let sync = DmaBufSync { flags };
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                iow(b'b', 0, mem::size_of::<DmaBufSync>()),
                &sync,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for Udmabuf {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.map.cast(), self.len);
        }
    }
}

struct NetdevBinding {
    id: u32,
    _socket: OwnedFd,
}

impl NetdevBinding {
    fn new(iface: &str, rxq: u32, dmabuf_fd: RawFd) -> io::Result<Self> {
        let iface = CString::new(iface)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface"))?;
        let ifindex = unsafe { libc::if_nametoindex(iface.as_bytes_with_nul().as_ptr().cast()) };
        if ifindex == 0 {
            let error = io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(0) {
                io::Error::from_raw_os_error(libc::ENODEV)
            } else {
                error
            });
        }
        let socket_raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if socket_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(socket_raw) };
        connect_netlink(socket.as_raw_fd())?;

        let mut seq = 1;
        let family_request = generic_request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 2, seq, |message| {
            put_attr(message, CTRL_ATTR_FAMILY_NAME, b"netdev\0")
        });
        send_message(socket.as_raw_fd(), &family_request)?;
        let family_reply = receive_reply(socket.as_raw_fd(), seq, GENL_ID_CTRL)?;
        let family_id = attr(&family_reply, CTRL_ATTR_FAMILY_ID)
            .and_then(read_u16)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EPROTO))?;

        seq += 1;
        let dmabuf_fd =
            u32::try_from(dmabuf_fd).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let bind_request = generic_request(
            family_id,
            NETDEV_CMD_BIND_RX,
            NETDEV_FAMILY_VERSION,
            seq,
            |message| {
                put_attr_u32(message, NETDEV_A_DMABUF_IFINDEX, ifindex);
                put_attr_u32(message, NETDEV_A_DMABUF_FD, dmabuf_fd);
                put_nested(message, NETDEV_A_DMABUF_QUEUES, |nested| {
                    put_attr_u32(nested, NETDEV_A_QUEUE_ID, rxq);
                    put_attr_u32(nested, NETDEV_A_QUEUE_TYPE, NETDEV_QUEUE_TYPE_RX);
                });
            },
        );
        send_message(socket.as_raw_fd(), &bind_request)?;
        let bind_reply = receive_reply(socket.as_raw_fd(), seq, family_id)?;
        let id = attr(&bind_reply, NETDEV_A_DMABUF_ID)
            .and_then(read_u32)
            .filter(|id| *id != 0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EPROTO))?;
        Ok(Self {
            id,
            _socket: socket,
        })
    }
}

struct Ring {
    ring: IoUring,
    host_ring: *mut BufRing,
    host_area: *mut u8,
    host_area_len: usize,
    copy_area: *mut u8,
    page_size: usize,
    setup_flags: u32,
}

impl Ring {
    fn new(page_size: usize) -> io::Result<Self> {
        let mut ring = unsafe { MaybeUninit::<IoUring>::zeroed().assume_init() };
        let mut params = IoUringParams {
            flags: IORING_SETUP_CQSIZE
                | IORING_SETUP_CQE32
                | IORING_SETUP_SINGLE_ISSUER
                | IORING_SETUP_DEFER_TASKRUN,
            cq_entries: 4096,
            ..Default::default()
        };
        negative(unsafe { io_uring_queue_init_params(64, &mut ring, &mut params) })?;
        let host_area_len = HOST_ENTRIES as usize * page_size;
        let host_area = match mmap(host_area_len) {
            Ok(map) => map,
            Err(error) => {
                unsafe { io_uring_queue_exit(&mut ring) };
                return Err(error);
            }
        };
        let copy_area = match mmap(page_size) {
            Ok(map) => map,
            Err(error) => {
                unsafe {
                    libc::munmap(host_area.cast(), host_area_len);
                    io_uring_queue_exit(&mut ring);
                }
                return Err(error);
            }
        };
        let copy_iovec = libc::iovec {
            iov_base: copy_area.cast(),
            iov_len: page_size,
        };
        if let Err(error) =
            negative(unsafe { io_uring_register_buffers(&mut ring, &copy_iovec, 1) })
        {
            unsafe {
                libc::munmap(copy_area.cast(), page_size);
                libc::munmap(host_area.cast(), host_area_len);
                io_uring_queue_exit(&mut ring);
            }
            return Err(error);
        }
        let mut error = 0;
        let host_ring = unsafe {
            io_uring_setup_buf_ring(
                &mut ring,
                HOST_ENTRIES.into(),
                HOST_BGID.into(),
                0,
                &mut error,
            )
        };
        if host_ring.is_null() {
            unsafe {
                io_uring_unregister_buffers(&mut ring);
                libc::munmap(copy_area.cast(), page_size);
                libc::munmap(host_area.cast(), host_area_len);
                io_uring_queue_exit(&mut ring);
            }
            return Err(io::Error::from_raw_os_error(-error));
        }
        let mut value = Self {
            ring,
            host_ring,
            host_area,
            host_area_len,
            copy_area,
            page_size,
            setup_flags: params.flags,
        };
        for bid in 0..HOST_ENTRIES {
            value.return_host_at(bid, bid as usize);
        }
        unsafe {
            (*value.host_ring)
                .tail
                .store(HOST_ENTRIES, Ordering::Release);
        }
        Ok(value)
    }

    fn get_sqe(&mut self) -> io::Result<&mut Sqe> {
        let head = unsafe { ptr::read_volatile(self.ring.sq.khead) };
        let tail = self.ring.sq.sqe_tail;
        if tail.wrapping_sub(head) >= self.ring.sq.ring_entries {
            return Err(io::Error::from_raw_os_error(libc::EAGAIN));
        }
        self.ring.sq.sqe_tail = tail.wrapping_add(1);
        let index = tail & self.ring.sq.ring_mask;
        Ok(unsafe { &mut *self.ring.sq.sqes.add(index as usize) })
    }

    fn submit_read(&mut self, fd: RawFd, len: u32, offset: u64, dmabuf_id: u32) -> io::Result<()> {
        self.get_sqe()?
            .prep_read(fd, len, offset, HOST_BGID, dmabuf_id, READ_DATA);
        self.submit_one()
    }

    fn submit_dontneed(
        &mut self,
        fd: RawFd,
        loan_id: u16,
        dmabuf_id: u32,
        token: u32,
    ) -> io::Result<()> {
        self.get_sqe()?
            .prep_dontneed(fd, loan_id, dmabuf_id, token, 1, DONTNEED_DATA);
        self.submit_one()
    }

    fn submit_copy(&mut self, fd: RawFd, key: u64, len: u32) -> io::Result<()> {
        let addr = self.copy_area as u64;
        self.get_sqe()?.prep_copy(fd, key, addr, len, COPY_DATA);
        self.submit_one()
    }

    fn copy_slice_mut(&mut self, len: usize) -> io::Result<&mut [u8]> {
        if len > self.page_size {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        Ok(unsafe { std::slice::from_raw_parts_mut(self.copy_area, len) })
    }

    fn submit_one(&mut self) -> io::Result<()> {
        let ret = unsafe { io_uring_submit(&mut self.ring) };
        if ret == 1 {
            Ok(())
        } else if ret < 0 {
            Err(io::Error::from_raw_os_error(-ret))
        } else {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }

    fn wait(&mut self) -> io::Result<*mut Cqe> {
        let mut cqe = ptr::null_mut();
        negative(unsafe { __io_uring_get_cqe(&mut self.ring, &mut cqe, 0, 1, ptr::null()) })?;
        Ok(cqe)
    }

    fn seen(&mut self) {
        let head = unsafe { &*(self.ring.cq.khead.cast::<AtomicU32>()) };
        let current = head.load(Ordering::Relaxed);
        head.store(current.wrapping_add(1), Ordering::Release);
    }

    fn host_slice(&self, bid: u16, len: usize) -> io::Result<&[u8]> {
        if bid >= HOST_ENTRIES || len > self.page_size {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        Ok(unsafe {
            std::slice::from_raw_parts(self.host_area.add(bid as usize * self.page_size), len)
        })
    }

    fn return_host_at(&mut self, bid: u16, offset: usize) {
        let tail = unsafe { (*self.host_ring).tail.load(Ordering::Relaxed) };
        let slot = (tail as usize + offset) & (HOST_ENTRIES as usize - 1);
        let buffer = unsafe { &mut *(self.host_ring.cast::<Buf>().add(slot)) };
        buffer.addr = unsafe { self.host_area.add(bid as usize * self.page_size) } as u64;
        buffer.len = self.page_size as u32;
        buffer.bid = bid;
    }

    fn return_host(&mut self, bid: u16) {
        self.return_host_at(bid, 0);
        unsafe {
            (*self.host_ring).tail.fetch_add(1, Ordering::Release);
        }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        fence(Ordering::SeqCst);
        unsafe {
            io_uring_free_buf_ring(
                &mut self.ring,
                self.host_ring,
                HOST_ENTRIES.into(),
                HOST_BGID.into(),
            );
            io_uring_unregister_buffers(&mut self.ring);
            io_uring_queue_exit(&mut self.ring);
            libc::munmap(self.copy_area.cast(), self.page_size);
            libc::munmap(self.host_area.cast(), self.host_area_len);
        }
    }
}

pub struct Devmem {
    ring: Ring,
    binding: NetdevBinding,
    memory: Udmabuf,
}

impl Devmem {
    pub fn new(iface: &str, rxq: u32) -> io::Result<Self> {
        let page_size = page_size()?;
        let memory = Udmabuf::new(page_size)?;
        let binding = NetdevBinding::new(iface, rxq, memory.fd.as_raw_fd())?;
        let ring = Ring::new(page_size)?;
        Ok(Self {
            ring,
            binding,
            memory,
        })
    }

    pub fn binding_id(&self) -> u32 {
        self.binding.id
    }

    pub fn setup_flags(&self) -> u32 {
        self.ring.setup_flags
    }

    pub fn read(
        &mut self,
        fd: RawFd,
        output: &mut [u8],
        offset: u64,
    ) -> io::Result<(usize, Stats)> {
        let length = u32::try_from(output.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length must fit u32"))?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "length must be nonzero",
            ));
        }
        self.ring.submit_read(fd, length, offset, self.binding.id)?;

        let mut received = 0usize;
        let mut pending_returns = 0u32;
        let mut pending_copies = 0u32;
        let mut terminal = None;
        let mut copy_error = None;
        let mut return_error = None;
        let mut stats = Stats::default();

        while terminal.is_none() || pending_returns != 0 || pending_copies != 0 {
            let cqe_ptr = self.ring.wait()?;
            let cqe = unsafe { &*cqe_ptr };
            let user_data = cqe.user_data;
            let result = cqe.res;
            let flags = cqe.flags;

            if user_data == DONTNEED_DATA {
                self.ring.seen();
                if pending_returns == 0 {
                    return Err(io::Error::from_raw_os_error(libc::EPROTO));
                }
                pending_returns -= 1;
                if result != 1 && return_error.is_none() {
                    return_error = Some(if result < 0 {
                        io::Error::from_raw_os_error(-result)
                    } else {
                        io::Error::from_raw_os_error(libc::EPROTO)
                    });
                }
                continue;
            }
            if user_data == COPY_DATA {
                self.ring.seen();
                if pending_copies == 0 {
                    return Err(io::Error::from_raw_os_error(libc::EPROTO));
                }
                pending_copies -= 1;
                if result <= 0 && return_error.is_none() {
                    return_error = Some(if result < 0 {
                        io::Error::from_raw_os_error(-result)
                    } else {
                        io::Error::from_raw_os_error(libc::EPROTO)
                    });
                }
                continue;
            }
            if user_data != READ_DATA || terminal.is_some() {
                self.ring.seen();
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
            if flags & IORING_CQE_F_MORE == 0 {
                self.ring.seen();
                if flags != 0 {
                    terminal = Some(Err(io::Error::from_raw_os_error(libc::EPROTO)));
                } else if result < 0 {
                    terminal = Some(Err(io::Error::from_raw_os_error(-result)));
                } else if result as usize != received {
                    terminal = Some(Err(io::Error::from_raw_os_error(libc::EPROTO)));
                } else {
                    terminal = Some(Ok(()));
                }
                continue;
            }
            if result <= 0 {
                self.ring.seen();
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
            let valid = result as usize;
            if flags & DATAFS_DEVMEM_CQE_F_COPY_REQUEST != 0 {
                if flags != IORING_CQE_F_MORE | DATAFS_DEVMEM_CQE_F_COPY_REQUEST
                    || valid > self.ring.page_size
                {
                    self.ring.seen();
                    return Err(io::Error::from_raw_os_error(libc::EPROTO));
                }
                let request = unsafe { *cqe_ptr.add(1).cast::<DatafsCopyCqe>() };
                let mut staged = vec![0; valid];
                if let Err(error) = self.memory.copy_to(request.frag_offset, &mut staged)
                    && copy_error.is_none()
                {
                    copy_error = Some(error);
                }
                self.ring.copy_slice_mut(valid)?.copy_from_slice(&staged);
                self.ring.seen();
                self.ring.submit_copy(fd, request.key, valid as u32)?;
                pending_copies = pending_copies
                    .checked_add(1)
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
                continue;
            }
            if valid > output.len() - received {
                self.ring.seen();
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
            let extra = unsafe { *cqe_ptr.add(1).cast::<DatafsCqe>() };
            if flags & IORING_CQE_F_BUFFER != 0 {
                let allowed = IORING_CQE_F_MORE
                    | IORING_CQE_F_BUFFER
                    | (u16::MAX as u32) << IORING_CQE_BUFFER_SHIFT;
                let bid = (flags >> IORING_CQE_BUFFER_SHIFT) as u16;
                if flags & !allowed != 0
                    || extra.frag_offset != 0
                    || extra.frag_token != 0
                    || extra.dmabuf_id != 0
                {
                    self.ring.seen();
                    return Err(io::Error::from_raw_os_error(libc::EPROTO));
                }
                let source = self.ring.host_slice(bid, valid)?;
                output[received..received + valid].copy_from_slice(source);
                received += valid;
                stats.fragments += 1;
                stats.host += 1;
                stats.host_bytes += valid as u64;
                self.ring.return_host(bid);
                self.ring.seen();
                continue;
            }

            if flags & 0xffff != IORING_CQE_F_MORE || extra.dmabuf_id != self.binding.id {
                self.ring.seen();
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
            if let Err(error) = self
                .memory
                .copy_to(extra.frag_offset, &mut output[received..received + valid])
                && copy_error.is_none()
            {
                copy_error = Some(error);
            }
            received += valid;
            stats.fragments += 1;
            stats.dmabuf += 1;
            stats.dmabuf_bytes += valid as u64;
            stats.tokens += 1;
            let loan_id = (flags >> DATAFS_DEVMEM_CQE_LOAN_SHIFT) as u16;
            let next_pending = pending_returns
                .checked_add(1)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            self.ring.seen();
            self.ring
                .submit_dontneed(fd, loan_id, extra.dmabuf_id, extra.frag_token)?;
            pending_returns = next_pending;
        }

        if let Some(error) = return_error {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "token return failed after {} bytes (host={}, dmabuf={}): {error}",
                    received, stats.host, stats.dmabuf
                ),
            ));
        }
        if let Some(error) = copy_error {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "dma-buf copy failed after {} bytes (host={}, dmabuf={}): {error}",
                    received, stats.host, stats.dmabuf
                ),
            ));
        }
        if let Err(error) = terminal.expect("loop requires a terminal completion") {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "read failed after {} bytes (host={}, dmabuf={}): {error}",
                    received, stats.host, stats.dmabuf
                ),
            ));
        }
        Ok((received, stats))
    }
}

impl Sqe {
    fn write_u16(&mut self, offset: usize, value: u16) {
        self.bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn write_i32(&mut self, offset: usize, value: i32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn write_u64(&mut self, offset: usize, value: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }

    fn prep_base(&mut self, fd: RawFd, op: u32, user_data: u64) {
        self.bytes.fill(0);
        self.bytes[0] = IORING_OP_URING_CMD;
        self.write_i32(4, fd);
        self.write_u32(8, op);
        self.write_u64(32, user_data);
    }

    fn prep_read(
        &mut self,
        fd: RawFd,
        len: u32,
        offset: u64,
        host_group: u16,
        dmabuf_id: u32,
        user_data: u64,
    ) {
        self.prep_base(fd, DATAFS_URING_CMD_RECV_DEVMEM, user_data);
        self.write_u32(24, len);
        self.write_u16(40, host_group);
        self.write_u32(44, dmabuf_id);
        self.write_u64(48, offset);
        self.write_u32(56, DATAFS_URING_F_WAIT_SOCKET);
    }

    fn prep_dontneed(
        &mut self,
        fd: RawFd,
        loan_id: u16,
        dmabuf_id: u32,
        token_start: u32,
        token_count: u32,
        user_data: u64,
    ) {
        self.prep_base(fd, DATAFS_URING_CMD_RECV_DEVMEM, user_data);
        self.write_u32(24, token_count);
        self.write_u16(40, loan_id);
        self.write_u32(44, dmabuf_id);
        self.write_u64(48, token_start.into());
        self.write_u32(56, DATAFS_URING_F_DEVMEM_DONTNEED);
    }

    fn prep_copy(&mut self, fd: RawFd, key: u64, addr: u64, len: u32, user_data: u64) {
        self.prep_base(fd, DATAFS_URING_CMD_COPY_RESPONSE, user_data);
        self.write_u64(16, addr);
        self.write_u32(24, len);
        self.write_u32(28, IORING_URING_CMD_FIXED);
        self.write_u16(40, 0);
        self.write_u64(48, key);
    }
}

fn negative(ret: i32) -> io::Result<i32> {
    if ret < 0 {
        Err(io::Error::from_raw_os_error(-ret))
    } else {
        Ok(ret)
    }
}

fn page_size() -> io::Result<usize> {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let value = usize::try_from(value).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    if !value.is_power_of_two() || value > u32::MAX as usize {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(value)
}

fn mmap(length: usize) -> io::Result<*mut u8> {
    let map = unsafe {
        libc::mmap(
            ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if map == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(map.cast())
    }
}

fn iow(kind: u8, number: u8, size: usize) -> libc::c_ulong {
    ((1u64 << 30) | ((size as u64) << 16) | ((kind as u64) << 8) | number as u64) as libc::c_ulong
}

fn connect_netlink(fd: RawFd) -> io::Result<()> {
    let mut local = unsafe { MaybeUninit::<libc::sockaddr_nl>::zeroed().assume_init() };
    local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let ret = unsafe {
        libc::bind(
            fd,
            (&raw const local).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut kernel = unsafe { MaybeUninit::<libc::sockaddr_nl>::zeroed().assume_init() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let ret = unsafe {
        libc::connect(
            fd,
            (&raw const kernel).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn generic_request(
    family: u16,
    command: u8,
    version: u8,
    seq: u32,
    attributes: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let mut message = vec![0; 20];
    message[4..6].copy_from_slice(&family.to_ne_bytes());
    message[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    message[8..12].copy_from_slice(&seq.to_ne_bytes());
    message[16] = command;
    message[17] = version;
    attributes(&mut message);
    let length = message.len() as u32;
    message[0..4].copy_from_slice(&length.to_ne_bytes());
    message
}

fn put_attr(message: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = 4 + value.len();
    message.extend_from_slice(&(length as u16).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(message.len().next_multiple_of(4), 0);
}

fn put_attr_u32(message: &mut Vec<u8>, kind: u16, value: u32) {
    put_attr(message, kind, &value.to_ne_bytes());
}

fn put_nested(message: &mut Vec<u8>, kind: u16, value: impl FnOnce(&mut Vec<u8>)) {
    let start = message.len();
    message.extend_from_slice(&[0; 4]);
    value(message);
    let length = (message.len() - start) as u16;
    message[start..start + 2].copy_from_slice(&length.to_ne_bytes());
    message[start + 2..start + 4].copy_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
    message.resize(message.len().next_multiple_of(4), 0);
}

fn send_message(fd: RawFd, message: &[u8]) -> io::Result<()> {
    let ret = unsafe { libc::send(fd, message.as_ptr().cast(), message.len(), 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if ret as usize != message.len() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(())
}

fn receive_reply(fd: RawFd, seq: u32, message_type: u16) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 65_536];
    loop {
        let received = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut offset = 0;
        let received = received as usize;
        while offset + 16 <= received {
            let length = read_u32(&buffer[offset..]).unwrap_or(0) as usize;
            if length < 16 || offset + length > received {
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
            let kind = read_u16(&buffer[offset + 4..]).unwrap();
            let reply_seq = read_u32(&buffer[offset + 8..]).unwrap();
            if reply_seq == seq {
                if kind == NLMSG_ERROR {
                    if length < 20 {
                        return Err(io::Error::from_raw_os_error(libc::EPROTO));
                    }
                    let error =
                        i32::from_ne_bytes(buffer[offset + 16..offset + 20].try_into().unwrap());
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(-error));
                    }
                } else if kind == message_type {
                    return Ok(buffer[offset..offset + length].to_vec());
                }
            }
            offset += length.next_multiple_of(4);
        }
    }
}

fn attr(message: &[u8], wanted: u16) -> Option<&[u8]> {
    if message.len() < 20 {
        return None;
    }
    let mut offset = 20;
    while offset + 4 <= message.len() {
        let length = read_u16(&message[offset..])? as usize;
        let kind = read_u16(&message[offset + 2..])? & NLA_TYPE_MASK;
        if length < 4 || offset + length > message.len() {
            return None;
        }
        if kind == wanted {
            return Some(&message[offset + 4..offset + length]);
        }
        offset += length.next_multiple_of(4);
    }
    None
}

fn read_u16(value: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(value.get(..2)?.try_into().ok()?))
}

fn read_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(value.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn ffi_layouts_match_linux_abi() {
        assert_eq!(mem::size_of::<IoUringSq>(), 104);
        assert_eq!(mem::size_of::<IoUringCq>(), 88);
        assert_eq!(mem::size_of::<IoUring>(), 216);
        assert_eq!(mem::offset_of!(IoUringSq, sqe_tail), 68);
        assert_eq!(mem::size_of::<IoUringParams>(), 120);
        assert_eq!(mem::size_of::<Sqe>(), 64);
        assert_eq!(mem::align_of::<Sqe>(), 8);
        assert_eq!(mem::size_of::<Cqe>(), 16);
        assert_eq!(mem::size_of::<Buf>(), 16);
        assert_eq!(mem::size_of::<BufRing>(), 16);
        assert_eq!(mem::size_of::<DatafsCqe>(), 16);
        assert_eq!(mem::offset_of!(DatafsCqe, frag_token), 8);
        assert_eq!(mem::offset_of!(DatafsCqe, dmabuf_id), 12);
        assert_eq!(mem::size_of::<UdmabufCreate>(), 24);
        assert_eq!(mem::offset_of!(UdmabufCreate, offset), 8);
        assert_eq!(mem::offset_of!(UdmabufCreate, size), 16);
        assert_eq!(mem::size_of::<DmaBufSync>(), 8);
    }

    #[test]
    fn generic_netlink_bind_request_has_nested_queue() {
        let request = generic_request(42, NETDEV_CMD_BIND_RX, 1, 7, |message| {
            put_attr_u32(message, NETDEV_A_DMABUF_IFINDEX, 3);
            put_attr_u32(message, NETDEV_A_DMABUF_FD, 9);
            put_nested(message, NETDEV_A_DMABUF_QUEUES, |nested| {
                put_attr_u32(nested, NETDEV_A_QUEUE_ID, 5);
                put_attr_u32(nested, NETDEV_A_QUEUE_TYPE, NETDEV_QUEUE_TYPE_RX);
            });
        });
        assert_eq!(read_u32(&request), Some(request.len() as u32));
        assert_eq!(read_u16(&request[4..]), Some(42));
        assert_eq!(request[16], NETDEV_CMD_BIND_RX);
        assert_eq!(
            attr(&request, NETDEV_A_DMABUF_IFINDEX).and_then(read_u32),
            Some(3)
        );
        let queues = attr(&request, NETDEV_A_DMABUF_QUEUES).unwrap();
        let mut nested = vec![0; 20];
        nested.extend_from_slice(queues);
        assert_eq!(attr(&nested, NETDEV_A_QUEUE_ID).and_then(read_u32), Some(5));
        assert_eq!(
            attr(&nested, NETDEV_A_QUEUE_TYPE).and_then(read_u32),
            Some(NETDEV_QUEUE_TYPE_RX)
        );
    }

    #[test]
    fn datafs_sqe_uses_command_payload() {
        let mut sqe = Sqe { bytes: [0; 64] };
        sqe.prep_read(7, 4096, 8192, 19, 23, READ_DATA);
        assert_eq!(sqe.bytes[0], IORING_OP_URING_CMD);
        assert_eq!(read_u32(&sqe.bytes[4..]), Some(7));
        assert_eq!(
            read_u32(&sqe.bytes[8..]),
            Some(DATAFS_URING_CMD_RECV_DEVMEM)
        );
        assert_eq!(read_u32(&sqe.bytes[24..]), Some(4096));
        assert_eq!(read_u16(&sqe.bytes[40..]), Some(19));
        assert_eq!(read_u32(&sqe.bytes[44..]), Some(23));
        assert_eq!(
            u64::from_ne_bytes(sqe.bytes[48..56].try_into().unwrap()),
            8192
        );
        assert_eq!(read_u32(&sqe.bytes[56..]), Some(DATAFS_URING_F_WAIT_SOCKET));
    }
}
