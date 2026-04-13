pub mod eth;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod tls;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}
