use std::net::Ipv6Addr;

pub const IPV6_HEADER_LEN: usize = 40;

pub fn payload_length(hdr: &[u8]) -> u16 {
    u16::from_be_bytes([hdr[4], hdr[5]])
}

pub fn next_header(hdr: &[u8]) -> u8 {
    hdr[6]
}

pub fn src_addr(hdr: &[u8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&hdr[8..24]);
    Ipv6Addr::from(octets)
}

pub fn dst_addr(hdr: &[u8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&hdr[24..40]);
    Ipv6Addr::from(octets)
}

pub fn set_payload_length(hdr: &mut [u8], len: u16) {
    let bytes = len.to_be_bytes();
    hdr[4] = bytes[0];
    hdr[5] = bytes[1];
}

pub fn pseudo_header(hdr: &[u8], tcp_len: u16) -> [u8; 40] {
    let mut ph = [0u8; 40];
    ph[0..16].copy_from_slice(&hdr[8..24]);
    ph[16..32].copy_from_slice(&hdr[24..40]);
    let len_bytes = (tcp_len as u32).to_be_bytes();
    ph[32..36].copy_from_slice(&len_bytes);
    ph[36] = 0;
    ph[37] = 0;
    ph[38] = 0;
    ph[39] = 6;
    ph
}
