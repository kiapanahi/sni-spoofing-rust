use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use tracing::info;
use windivert::prelude::*;

use super::RawBackend;
use crate::error::SnifferError;

pub struct WinDivertBackend {
    inject_handle: WinDivert<NetworkLayer>,
    packet_rx: Receiver<Vec<u8>>,
}

impl WinDivertBackend {
    pub fn open(upstreams: &[SocketAddr]) -> Result<Self, SnifferError> {
        let mut parts = Vec::new();
        for addr in upstreams {
            let ip = addr.ip();
            let port = addr.port();
            match ip {
                std::net::IpAddr::V4(v4) => {
                    parts.push(format!(
                        "(ip.SrcAddr == {0} and tcp.SrcPort == {1}) or (ip.DstAddr == {0} and tcp.DstPort == {1})",
                        v4, port
                    ));
                }
                std::net::IpAddr::V6(v6) => {
                    parts.push(format!(
                        "(ipv6.SrcAddr == {0} and tcp.SrcPort == {1}) or (ipv6.DstAddr == {0} and tcp.DstPort == {1})",
                        v6, port
                    ));
                }
            }
        }
        let filter_str = format!("tcp and ({})", parts.join(" or "));
        info!(filter = %filter_str, "opening WinDivert handles");

        let sniff_flags = WinDivertFlags::new().set_sniff().set_recv_only();
        let sniff_handle = WinDivert::network(
            &filter_str,
            0i16,
            sniff_flags,
        ).map_err(|e| SnifferError::SocketOpen(io::Error::new(io::ErrorKind::Other, format!("sniff handle: {}", e))))?;

        let inject_flags = WinDivertFlags::new().set_send_only();
        let inject_handle = WinDivert::network(
            "false",
            0i16,
            inject_flags,
        ).map_err(|e| SnifferError::SocketOpen(io::Error::new(io::ErrorKind::Other, format!("inject handle: {}", e))))?;

        let (packet_tx, packet_rx) = mpsc::sync_channel(128);
        thread::spawn(move || {
            let mut recv_buf = vec![0u8; 65536];
            loop {
                let packet = match sniff_handle.recv(&mut recv_buf) {
                    Ok(packet) => packet,
                    Err(_) => return,
                };

                if packet_tx.send(packet.data.to_vec()).is_err() {
                    return;
                }
            }
        });

        info!("WinDivert handles opened (sniff + inject)");
        Ok(WinDivertBackend {
            inject_handle,
            packet_rx,
        })
    }
}

impl RawBackend for WinDivertBackend {
    fn frame_kind(&self) -> crate::packet::FrameKind { crate::packet::FrameKind::RawIp }

    fn skip_checksum_on_send(&self) -> bool { false }

    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, SnifferError> {
        let data = match self.packet_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(packet) => packet,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(SnifferError::Recv(io::Error::new(io::ErrorKind::TimedOut, "recv timeout")));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(SnifferError::Recv(io::Error::new(io::ErrorKind::BrokenPipe, "sniff thread stopped")));
            }
        };

        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), SnifferError> {
        let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(frame.to_vec()) };
        packet.address.set_outbound(true);
        let _ = packet.recalculate_checksums(Default::default());
        self.inject_handle.send(&packet)
            .map_err(|e| SnifferError::Inject(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
        Ok(())
    }
}
