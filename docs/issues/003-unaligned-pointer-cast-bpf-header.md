# Issue 003: Unaligned pointer cast in macOS BPF header parsing (UB)

**Severity:** Bug  
**File:** `src/sniffer/macos.rs:109`

## Description

```rust
let hdr = unsafe { &*(remaining.as_ptr() as *const BpfHdr) };
```

`remaining` is a slice into a byte buffer with no alignment guarantee. `BpfHdr` contains `u32` fields requiring 4-byte alignment. Casting an unaligned pointer to `&BpfHdr` is undefined behavior in Rust, even if ARM64 hardware handles unaligned loads silently.

From the Rust reference: creating a reference to an unaligned value is instant UB, regardless of whether the reference is ever dereferenced.

## Impact

Undefined behavior. In practice, Apple Silicon handles unaligned loads in hardware, so this likely works today. But the compiler is free to optimize based on the alignment guarantee, potentially generating incorrect code in future Rust versions or with different optimization flags.

## Suggested Fix

**Option A** — read fields individually using `from_ne_bytes` (BPF headers use host byte order):

```rust
fn read_bpf_hdr(data: &[u8]) -> Option<(u32, u32, u16)> {
    if data.len() < 18 {
        return None;
    }
    let bh_caplen = u32::from_ne_bytes(data[8..12].try_into().ok()?);
    let bh_datalen = u32::from_ne_bytes(data[12..16].try_into().ok()?);
    let bh_hdrlen = u16::from_ne_bytes(data[16..18].try_into().ok()?);
    Some((bh_caplen, bh_datalen, bh_hdrlen))
}
```

**Option B** — use `std::ptr::read_unaligned`:

```rust
let hdr = unsafe { std::ptr::read_unaligned(remaining.as_ptr() as *const BpfHdr) };
```

Option A is preferred as it avoids `unsafe` entirely.
