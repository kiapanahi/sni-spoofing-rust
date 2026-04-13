use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;

use tracing::info;

use crate::error::SnifferError;
use super::RawBackend;

pub struct BpfBackend {
    fd: RawFd,
    buf_len: usize,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_len: usize,
}

const BIOCSETIF: libc::c_ulong = 0x8020426C;
const BIOCIMMEDIATE: libc::c_ulong = 0x80044270;
const BIOCSHDRCMPLT: libc::c_ulong = 0x80044275;
const BIOCGBLEN: libc::c_ulong = 0x40044266;
const BIOCSETF: libc::c_ulong = 0x80104267;
const BIOCSRTIMEOUT: libc::c_ulong = 0x8010426D;

#[repr(C)]
struct BpfHdr {
    bh_tstamp_sec: u32,
    bh_tstamp_usec: u32,
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: u16,
}

fn bpf_wordalign(x: usize) -> usize {
    (x + 3) & !3
}

impl BpfBackend {
    pub fn open(upstreams: &[SocketAddr]) -> Result<Self, SnifferError> {
        let first = upstreams.first().expect("no upstreams");
        let ifname = get_interface_for(first.ip())?;
        info!(interface = %ifname, "binding BPF device");

        let fd = open_bpf_device()?;

        let mut buf_len: libc::c_uint = 0;
        if unsafe { libc::ioctl(fd, BIOCGBLEN, &mut buf_len) } < 0 {
            unsafe { libc::close(fd) };
            return Err(SnifferError::SocketOpen(io::Error::last_os_error()));
        }

        let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
        let name_bytes = ifname.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifreq.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
        }
        if unsafe { libc::ioctl(fd, BIOCSETIF, &ifreq) } < 0 {
            unsafe { libc::close(fd) };
            return Err(SnifferError::SocketBind(io::Error::last_os_error()));
        }

        let flag: libc::c_uint = 1;
        if unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &flag) } < 0 {
            unsafe { libc::close(fd) };
            return Err(SnifferError::Other("BIOCIMMEDIATE failed".into()));
        }

        if unsafe { libc::ioctl(fd, BIOCSHDRCMPLT, &flag) } < 0 {
            unsafe { libc::close(fd) };
            return Err(SnifferError::Other("BIOCSHDRCMPLT failed".into()));
        }

        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        if unsafe { libc::ioctl(fd, BIOCSRTIMEOUT, &tv) } < 0 {
            unsafe { libc::close(fd) };
            return Err(SnifferError::Other("BIOCSRTIMEOUT failed".into()));
        }

        attach_bpf_filter(fd)?;

        let buf_len = buf_len as usize;
        Ok(BpfBackend {
            fd,
            buf_len,
            read_buf: vec![0u8; buf_len],
            read_pos: 0,
            read_len: 0,
        })
    }
}

impl RawBackend for BpfBackend {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, SnifferError> {
        loop {
            if self.read_pos < self.read_len {
                let remaining = &self.read_buf[self.read_pos..self.read_len];
                if remaining.len() >= mem::size_of::<BpfHdr>() {
                    let hdr = unsafe { &*(remaining.as_ptr() as *const BpfHdr) };
                    let hdr_len = hdr.bh_hdrlen as usize;
                    let cap_len = hdr.bh_caplen as usize;
                    let total = bpf_wordalign(hdr_len + cap_len);

                    if self.read_pos + hdr_len + cap_len <= self.read_len {
                        let frame_start = self.read_pos + hdr_len;
                        let copy_len = cap_len.min(buf.len());
                        buf[..copy_len].copy_from_slice(
                            &self.read_buf[frame_start..frame_start + copy_len],
                        );
                        self.read_pos += total;
                        return Ok(copy_len);
                    }
                }
                self.read_pos = 0;
                self.read_len = 0;
            }

            let n = unsafe {
                libc::read(
                    self.fd,
                    self.read_buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf_len,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut
                    || err.raw_os_error() == Some(libc::EAGAIN)
                {
                    return Err(SnifferError::Recv(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "timeout",
                    )));
                }
                return Err(SnifferError::Recv(err));
            }
            if n == 0 {
                return Err(SnifferError::Recv(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "empty read",
                )));
            }
            self.read_pos = 0;
            self.read_len = n as usize;
        }
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), SnifferError> {
        let ret = unsafe {
            libc::write(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
            )
        };
        if ret < 0 {
            return Err(SnifferError::Inject(io::Error::last_os_error()));
        }
        Ok(())
    }
}

impl Drop for BpfBackend {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn open_bpf_device() -> Result<RawFd, SnifferError> {
    for i in 0..100 {
        let path = format!("/dev/bpf{}\0", i);
        let fd = unsafe {
            libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDWR)
        };
        if fd >= 0 {
            info!(device = %format!("/dev/bpf{}", i), "opened BPF device");
            return Ok(fd);
        }
    }
    Err(SnifferError::SocketOpen(io::Error::new(
        io::ErrorKind::NotFound,
        "no available /dev/bpf device",
    )))
}

fn get_interface_for(ip: IpAddr) -> Result<String, SnifferError> {
    use std::net::UdpSocket;

    let target = match ip {
        IpAddr::V4(v4) => format!("{}:53", v4),
        IpAddr::V6(v6) => format!("[{}]:53", v6),
    };

    let sock = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .map_err(|e| SnifferError::Other(format!("bind UDP: {}", e)))?;
    sock.connect(&target)
        .map_err(|e| SnifferError::Other(format!("connect UDP: {}", e)))?;
    let local_ip = sock.local_addr()
        .map_err(|e| SnifferError::Other(format!("local addr: {}", e)))?
        .ip();

    let addrs = nix::ifaddrs::getifaddrs()
        .map_err(|e| SnifferError::Other(format!("getifaddrs: {}", e)))?;
    for ifaddr in addrs {
        if let Some(addr) = ifaddr.address {
            let matches = match (addr.as_sockaddr_in(), addr.as_sockaddr_in6()) {
                (Some(v4), _) => IpAddr::V4(v4.ip().into()) == local_ip,
                (_, Some(v6)) => IpAddr::V6(v6.ip()) == local_ip,
                _ => false,
            };
            if matches {
                return Ok(ifaddr.interface_name.clone());
            }
        }
    }

    Err(SnifferError::Other(format!(
        "no interface found for local IP {}",
        local_ip
    )))
}

fn attach_bpf_filter(fd: RawFd) -> Result<(), SnifferError> {
    #[repr(C)]
    struct BpfInsn {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    let filter: Vec<BpfInsn> = vec![
        BpfInsn { code: 0x28, jt: 0, jf: 0, k: 12 },
        BpfInsn { code: 0x15, jt: 0, jf: 3, k: 0x0800 },
        BpfInsn { code: 0x30, jt: 0, jf: 0, k: 23 },
        BpfInsn { code: 0x15, jt: 4, jf: 5, k: 6 },
        BpfInsn { code: 0x15, jt: 0, jf: 4, k: 0x86DD },
        BpfInsn { code: 0x30, jt: 0, jf: 0, k: 20 },
        BpfInsn { code: 0x15, jt: 1, jf: 2, k: 6 },
        BpfInsn { code: 0x06, jt: 0, jf: 0, k: 0xFFFF },
        BpfInsn { code: 0x06, jt: 0, jf: 0, k: 0 },
    ];

    #[repr(C)]
    struct BpfProgram {
        bf_len: u32,
        bf_insns: *const BpfInsn,
    }

    let prog = BpfProgram {
        bf_len: filter.len() as u32,
        bf_insns: filter.as_ptr(),
    };

    if unsafe { libc::ioctl(fd, BIOCSETF, &prog) } < 0 {
        return Err(SnifferError::FilterAttach(io::Error::last_os_error()));
    }

    info!("BPF filter attached (TCP only)");
    Ok(())
}
