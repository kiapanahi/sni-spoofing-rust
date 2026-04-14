# Issue 008: BPF filter doesn't filter by upstream IP on Linux/macOS

**Severity:** Design Issue  
**Files:** `src/sniffer/linux.rs:161`, `src/sniffer/macos.rs:234`

## Description

The BPF filter on Linux and macOS only matches "is this TCP?". It accepts every TCP packet on the interface. Filtering by upstream IP/port is done in userspace (`parse_frame`).

```rust
// linux.rs:161
fn attach_bpf_filter(fd: RawFd, _upstreams: &[SocketAddr]) -> Result<(), SnifferError> {
    // _upstreams is accepted but IGNORED
    let filter: Vec<libc::sock_filter> = vec![
        // ... only checks ethertype + protocol == TCP
    ];
```

The Windows backend correctly includes IP/port filtering in the WinDivert filter string (`windows.rs:25-36`).

## Impact

On a busy machine, the sniffer receives and processes thousands of irrelevant TCP packets per second. Each packet goes through `parse_frame` which does hash lookups on the upstream set, only to be discarded. This wastes CPU and adds latency to the processing of relevant packets.

## Suggested Fix

Generate BPF bytecode dynamically to include IP + port checks. For a single upstream `1.2.3.4:443`, the equivalent `tcpdump` filter is:

```
tcp and (host 1.2.3.4 and port 443)
```

This compiles to approximately 20 BPF instructions. Either:

1. Use `libpcap`'s `pcap_compile` to generate the bytecode at runtime
2. Generate the bytecode manually based on the upstream addresses:

```rust
fn build_bpf_filter(upstreams: &[SocketAddr]) -> Vec<libc::sock_filter> {
    let mut insns = Vec::new();
    
    // Check ethertype == IPv4 (0x0800) or IPv6 (0x86dd)
    // Check protocol == TCP (6)
    // For each upstream:
    //   Check (src_ip == upstream_ip && src_port == upstream_port)
    //   OR    (dst_ip == upstream_ip && dst_port == upstream_port)
    // Accept if any match, reject otherwise
    
    todo!()
}
```

The `_upstreams` parameter is already threaded through to `attach_bpf_filter` on Linux, so the plumbing is ready.
