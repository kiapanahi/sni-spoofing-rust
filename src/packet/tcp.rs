pub const TCP_MIN_HEADER_LEN: usize = 20;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

pub fn data_offset(hdr: &[u8]) -> usize {
    (hdr[12] >> 4) as usize * 4
}

pub fn src_port(hdr: &[u8]) -> u16 {
    u16::from_be_bytes([hdr[0], hdr[1]])
}

pub fn dst_port(hdr: &[u8]) -> u16 {
    u16::from_be_bytes([hdr[2], hdr[3]])
}

pub fn seq_num(hdr: &[u8]) -> u32 {
    u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]])
}

pub fn ack_num(hdr: &[u8]) -> u32 {
    u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]])
}

pub fn flags(hdr: &[u8]) -> u8 {
    hdr[13]
}

pub fn set_seq_num(hdr: &mut [u8], seq: u32) {
    let bytes = seq.to_be_bytes();
    hdr[4..8].copy_from_slice(&bytes);
}

pub fn set_flags(hdr: &mut [u8], f: u8) {
    hdr[13] = f;
}

pub fn add_flag(hdr: &mut [u8], f: u8) {
    hdr[13] |= f;
}

pub fn payload_len(hdr: &[u8], total_tcp_len: usize) -> usize {
    total_tcp_len.saturating_sub(data_offset(hdr))
}

pub fn ones_complement_sum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn recompute_checksum_v4(ip_hdr: &[u8], tcp_segment: &mut [u8]) {
    tcp_segment[16] = 0;
    tcp_segment[17] = 0;

    let pseudo = super::ipv4::pseudo_header(ip_hdr, tcp_segment.len() as u16);

    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < pseudo.len() {
        sum += u16::from_be_bytes([pseudo[i], pseudo[i + 1]]) as u32;
        i += 2;
    }
    i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    let bytes = cksum.to_be_bytes();
    tcp_segment[16] = bytes[0];
    tcp_segment[17] = bytes[1];
}

pub fn recompute_checksum_v6(ip_hdr: &[u8], tcp_segment: &mut [u8]) {
    tcp_segment[16] = 0;
    tcp_segment[17] = 0;

    let pseudo = super::ipv6::pseudo_header(ip_hdr, tcp_segment.len() as u16);

    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < pseudo.len() {
        sum += u16::from_be_bytes([pseudo[i], pseudo[i + 1]]) as u32;
        i += 2;
    }
    i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    let bytes = cksum.to_be_bytes();
    tcp_segment[16] = bytes[0];
    tcp_segment[17] = bytes[1];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ones_complement_basic() {
        let result = ones_complement_sum(&[0x00, 0x01]);
        assert_eq!(result, 0xFFFE);
    }

    #[test]
    fn test_ones_complement_odd_length() {
        let result = ones_complement_sum(&[0x00, 0x01, 0x02]);
        assert_eq!(result, 0xFDFE);
    }
}
