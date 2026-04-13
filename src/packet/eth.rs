use super::IpVersion;

pub const ETH_HEADER_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

pub fn ethertype(frame: &[u8]) -> Option<IpVersion> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }
    let et = u16::from_be_bytes([frame[12], frame[13]]);
    match et {
        ETHERTYPE_IPV4 => Some(IpVersion::V4),
        ETHERTYPE_IPV6 => Some(IpVersion::V6),
        _ => None,
    }
}
