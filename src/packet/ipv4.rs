use std::net::Ipv4Addr;

pub const IPV4_MIN_HEADER_LEN: usize = 20;

pub fn header_len(hdr: &[u8]) -> usize {
    (hdr[0] & 0x0f) as usize * 4
}

pub fn total_length(hdr: &[u8]) -> u16 {
    u16::from_be_bytes([hdr[2], hdr[3]])
}

pub fn protocol(hdr: &[u8]) -> u8 {
    hdr[9]
}

pub fn src_addr(hdr: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(hdr[12], hdr[13], hdr[14], hdr[15])
}

pub fn dst_addr(hdr: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(hdr[16], hdr[17], hdr[18], hdr[19])
}

pub fn set_total_length(hdr: &mut [u8], len: u16) {
    let bytes = len.to_be_bytes();
    hdr[2] = bytes[0];
    hdr[3] = bytes[1];
}

pub fn increment_ident(hdr: &mut [u8]) {
    let id = u16::from_be_bytes([hdr[4], hdr[5]]).wrapping_add(1);
    let bytes = id.to_be_bytes();
    hdr[4] = bytes[0];
    hdr[5] = bytes[1];
}

pub fn recompute_checksum(hdr: &mut [u8]) {
    let ihl = header_len(hdr);
    hdr[10] = 0;
    hdr[11] = 0;
    let cksum = super::tcp::ones_complement_sum(&hdr[..ihl]);
    let bytes = cksum.to_be_bytes();
    hdr[10] = bytes[0];
    hdr[11] = bytes[1];
}

pub fn pseudo_header(hdr: &[u8], tcp_len: u16) -> [u8; 12] {
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(&hdr[12..16]);
    ph[4..8].copy_from_slice(&hdr[16..20]);
    ph[8] = 0;
    ph[9] = 6;
    let len_bytes = tcp_len.to_be_bytes();
    ph[10] = len_bytes[0];
    ph[11] = len_bytes[1];
    ph
}
