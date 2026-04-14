# Issue 015: `ones_complement_sum` lives in `tcp.rs` but is used by `ipv4.rs`

**Severity:** Code Smell  
**Files:** `src/packet/tcp.rs:50-64`, `src/packet/ipv4.rs:43`

## Description

The IP header checksum is calculated by calling into `tcp.rs`:

```rust
// ipv4.rs:43
let cksum = super::tcp::ones_complement_sum(&hdr[..ihl]);
```

`ones_complement_sum` is a generic checksum utility that applies to both IP and TCP headers. Having `ipv4.rs` reach into `tcp.rs` for it is a layering violation — IP is a lower layer than TCP.

## Suggested Fix

Move the checksum utility to a shared location:

```rust
// packet/checksum.rs (new file)
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
```

Then both `ipv4.rs` and `tcp.rs` import from `super::checksum::ones_complement_sum`.

Update `packet/mod.rs`:

```rust
pub mod checksum;
pub mod eth;
pub mod ipv4;
// ...
```
