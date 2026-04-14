# Issue 017: `WinDivertPacket::new` called with unvalidated bytes

**Severity:** Code Smell  
**File:** `src/sniffer/windows.rs:79`

## Description

```rust
let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(frame.to_vec()) };
```

The `unsafe` contract for `WinDivertPacket::<NetworkLayer>::new` requires `frame` to be a valid network-layer packet. `frame` comes from `build_fake_frame` which does raw byte manipulation. If any math is wrong in `build_fake_frame` (e.g., `total_length` overflows `u16`, headers are truncated, or `ip_hdr_len + tcp_hdr_len + fake_payload.len()` exceeds `u16::MAX`), the bytes are not a valid packet and this is UB.

## Impact

Currently unlikely to trigger since the fake payload is always 517 bytes and headers are well-formed. But there's no defense against future changes to `build_fake_frame` or unusual configurations.

## Suggested Fix

Add a validation step before the unsafe call:

```rust
fn validate_ip_packet(frame: &[u8]) -> bool {
    if frame.len() < 20 { return false; }
    let version = frame[0] >> 4;
    match version {
        4 => {
            if frame.len() < 20 { return false; }
            let ihl = (frame[0] & 0x0f) as usize * 4;
            let total_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
            ihl >= 20 && total_len == frame.len() && frame.len() >= ihl
        }
        6 => {
            if frame.len() < 40 { return false; }
            let payload_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
            payload_len + 40 == frame.len()
        }
        _ => false,
    }
}
```

Then use it:

```rust
debug_assert!(
    validate_ip_packet(&fake_frame),
    "build_fake_frame produced invalid packet: len={}",
    fake_frame.len()
);
// SAFETY: validated that fake_frame is a well-formed IP packet above.
let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(fake_frame) };
```
