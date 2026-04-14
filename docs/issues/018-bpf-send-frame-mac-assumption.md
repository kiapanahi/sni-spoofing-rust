# Issue 018: macOS BPF `send_frame` assumes captured frame has correct outbound MACs

**Severity:** Code Smell  
**Files:** `src/sniffer/macos.rs:159-171`, `src/sniffer/mod.rs:56-57`

## Description

`build_fake_frame` copies the link-layer header (Ethernet, 14 bytes) from the captured template frame (the 3rd ACK). Since `BIOCSHDRCMPLT` is set on the BPF device (`macos.rs:74`), the kernel won't auto-fill the source MAC address. The injected frame goes out with whatever MACs were in the template.

This works correctly only if:
1. The template was an outbound packet (src MAC = local interface, dst MAC = gateway)
2. The interface's MAC hasn't changed since the packet was captured

Neither assumption is validated.

## Impact

If for any reason the template frame's Ethernet header has incorrect MACs (e.g., a race condition causes an inbound SYN-ACK to be used as the template instead of the outbound ACK), the injected fake packet would have swapped MACs and be dropped by the gateway or looped back.

In practice, the sniffer logic ensures only the outbound ACK (3rd handshake packet) is used as the template, so this is unlikely to trigger. But the assumption is implicit and undocumented.

## Suggested Fix

Either query the interface's MAC at startup and set it explicitly, or add an assertion:

```rust
// In build_fake_frame, document the invariant:
/// Builds a fake frame from the template of an OUTBOUND ACK packet.
/// The link-layer header (Ethernet src/dst MACs) is copied directly
/// from the template. The caller must ensure the template is outbound.
fn build_fake_frame(...) -> Vec<u8> {
    // ...
}
```

Or store the gateway MAC during the SYN phase and set it explicitly:

```rust
struct ConnState {
    // ...existing fields...
    gateway_mac: Option<[u8; 6]>,  // captured from outbound SYN
}

// In build_fake_frame, overwrite the dst MAC:
if frame_kind == FrameKind::Ethernet {
    if let Some(mac) = gateway_mac {
        out[0..6].copy_from_slice(&mac);
    }
}
```
