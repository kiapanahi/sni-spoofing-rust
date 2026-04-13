use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;

use tracing::info;

use crate::error::SnifferError;
use super::RawBackend;

pub struct AfPacketBackend {
    fd: RawFd,
    ifindex: i32,
}

impl AfPacketBackend {
    pub fn open(upstreams: &[SocketAddr]) -> Result<Self, SnifferError> {
        let first = upstreams.first().expect("no upstreams");
        let (ifname, ifindex) = get_interface_for(first.ip())?;
        info!(interface = %ifname, ifindex, "binding AF_PACKET socket");

        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(SnifferError::SocketOpen(io::Error::last_os_error()));
        }

        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex;

        let ret = unsafe {
            libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(SnifferError::SocketBind(io::Error::last_os_error()));
        }

        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                mem::size_of::<libc::timeval>() as u32,
            );
        }

        attach_bpf_filter(fd, upstreams)?;

        Ok(AfPacketBackend { fd, ifindex })
    }
}

impl RawBackend for AfPacketBackend {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, SnifferError> {
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(SnifferError::Recv(io::Error::last_os_error()));
        }
        Ok(n as usize)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), SnifferError> {
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        sll.sll_ifindex = self.ifindex;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&frame[0..6]);

        let ret = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            return Err(SnifferError::Inject(io::Error::last_os_error()));
        }
        Ok(())
    }
}

impl Drop for AfPacketBackend {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn get_interface_for(ip: IpAddr) -> Result<(String, i32), SnifferError> {
    use std::net::UdpSocket;

    let target = match ip {
        IpAddr::V4(v4) => format!("{}:53", v4),
        IpAddr::V6(v6) => format!("[{}]:53", v6),
    };

    let sock = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .map_err(|e| SnifferError::Other(format!("bind UDP: {}", e)))?;
    sock.connect(&target)
        .map_err(|e| SnifferError::Other(format!("connect UDP to {}: {}", target, e)))?;
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
                let ifname = ifaddr.interface_name.clone();
                let ifindex = nix::net::if_::if_nametoindex(ifname.as_str())
                    .map_err(|e| SnifferError::Other(format!("if_nametoindex: {}", e)))?;
                return Ok((ifname, ifindex as i32));
            }
        }
    }

    Err(SnifferError::Other(format!(
        "no interface found for local IP {}",
        local_ip
    )))
}

fn attach_bpf_filter(fd: RawFd, _upstreams: &[SocketAddr]) -> Result<(), SnifferError> {
    let filter: Vec<libc::sock_filter> = vec![
        libc::sock_filter { code: 0x28, jt: 0, jf: 0, k: 0x0000000c },
        libc::sock_filter { code: 0x15, jt: 0, jf: 2, k: 0x00000800 },
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 0x00000017 },
        libc::sock_filter { code: 0x15, jt: 6, jf: 7, k: 0x00000006 },
        libc::sock_filter { code: 0x15, jt: 0, jf: 6, k: 0x000086dd },
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 0x00000014 },
        libc::sock_filter { code: 0x15, jt: 3, jf: 0, k: 0x00000006 },
        libc::sock_filter { code: 0x15, jt: 0, jf: 3, k: 0x0000002c },
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 0x00000036 },
        libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 0x00000006 },
        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00040000 },
        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00000000 },
    ];

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const libc::sock_fprog as *const libc::c_void,
            mem::size_of::<libc::sock_fprog>() as u32,
        )
    };
    if ret < 0 {
        return Err(SnifferError::FilterAttach(io::Error::last_os_error()));
    }

    info!("BPF filter attached (TCP only)");
    Ok(())
}
