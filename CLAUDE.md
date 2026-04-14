# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build --release

# Run (config path is the only argument; defaults to config.json)
sudo ./target/release/sni-spoof-rs config.json   # Linux/macOS
./target/release/sni-spoof-rs.exe config.json    # Windows (as Administrator)

# Test (only packet/tls.rs has unit tests)
cargo test
cargo test -- packet::tls   # run just TLS tests

# Debug logging
RUST_LOG=debug cargo run -- config.json

# Lint
cargo clippy
```

On Windows, building requires the WinDivert static lib. The `windivert` crate handles this via its build script — no manual setup needed.

## Architecture

The program has two concurrent systems that communicate over channels:

```
Client → Listener (tokio async) → Handler → Upstream TCP
                                      ↕
                              Sniffer (std::thread, blocking)
                         raw packet capture + fake packet injection
```

**Why async + sync?** Handlers are I/O-bound (tokio is correct). The sniffer loops on `backend.recv_frame()` which is a blocking kernel call — a dedicated OS thread avoids blocking the tokio executor.

### Channel types — a critical constraint

There are two channel directions between handler and sniffer:

| Direction | Type | Why |
|-----------|------|-----|
| Handler → Sniffer (commands) | `std::sync::mpsc` | Handler is async, `send()` is non-blocking |
| Sniffer → Handler (results) | `tokio::sync::mpsc` | Handler `await`s the result |

The sniffer calls `tokio::sync::mpsc::Sender::blocking_send()` — this **panics if called from a tokio context**. The sniffer must stay on a bare `std::thread`. Do not move `run_sniffer` into `spawn_blocking` or a tokio task.

### Sniffer loop (`src/sniffer/mod.rs`)

Single-threaded, polling loop:
1. Drain `cmd_rx` (all pending `Register`/`Deregister`)
2. `backend.recv_frame()` with 100 ms timeout
3. Parse frame → match against `connections: HashMap<ConnId, ConnState>`
4. State machine per connection:
   - Outbound SYN → record `isn`
   - Outbound 3rd ACK (pure ACK, seq == isn+1) → `thread::sleep(1ms)`, inject fake ClientHello with `seq = isn+1 - len(fake)`
   - Inbound SYN-ACK → record `server_isn`
   - Inbound ACK (ack == isn+1, after fake injected) → send `FakeConfirmed`, remove from map
   - Inbound RST → send `Failed`, remove from map

`ConnId` is the 4-tuple keyed as the **outbound** direction (local→upstream), even when processing inbound packets.

### Handler flow (`src/handler.rs`)

1. Build `fake_payload` = `tls::build_client_hello(fake_sni)` (always 517 bytes)
2. Create upstream `socket2::Socket`, bind to get an ephemeral port
3. Send `Register` to sniffer; await `registered_rx` oneshot before connecting (ensures sniffer is ready before the SYN goes out)
4. Non-blocking `connect()`, then `upstream.writable()` with 5 s timeout
5. Await `result_rx` with 2 s timeout for `FakeConfirmed` or `Failed`
6. Call `relay::relay(client, upstream)`

### Platform backends (`src/sniffer/{linux,macos,windows}.rs`)

All implement `RawBackend` from `src/sniffer/mod.rs`:

```rust
pub trait RawBackend: Send + 'static {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, SnifferError>;
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), SnifferError>;
    fn frame_kind(&self) -> FrameKind;
    fn skip_checksum_on_send(&self) -> bool { false }
}
```

| Platform | Mechanism | Frame type | Privilege |
|----------|-----------|-----------|-----------|
| Linux | AF_PACKET raw socket + BPF filter (TCP only) | Ethernet (has MAC) | `CAP_NET_RAW` / root |
| macOS | `/dev/bpf*` + BPF filter | Ethernet (has MAC) | root |
| Windows | WinDivert kernel driver (`windivert = "0.7.0-beta"`) | RawIP (no Ethernet) | Administrator |

`FrameKind` (`src/packet/mod.rs`) drives `link_header_len()` — Linux/macOS return 14 (Ethernet), Windows returns 0.

### Packet layer (`src/packet/`)

- `mod.rs` — `FrameKind`, `IpVersion`, frame type detection
- `eth.rs` — EtherType detection (0x0800 IPv4, 0x86DD IPv6)
- `ipv4.rs` / `ipv6.rs` — header field accessors, length/checksum updates
- `tcp.rs` — header parsing, flag constants (`SYN`, `ACK`, `RST`, `FIN`, `PSH`), checksum recompute (ones-complement, with pseudo-header)
- `tls.rs` — builds a fixed 517-byte fake ClientHello from a hardcoded template; `parse_sni` only works on self-generated packets (hardcoded byte offsets into the template)

### Fake ClientHello construction

`tls::build_client_hello(sni)` always produces exactly 517 bytes by padding with a TLS `padding` extension (type `0x0015`) to fill up to SNI length 219. Randomizes `random`, `session_id`, and the key share. The template SNI is `mci.ir` (6 bytes); the function splices in the caller's SNI and adjusts length fields manually.

## Known issues

Active issues are documented in `docs/issues/`. The most impactful ones:

- **#001** — `relay::relay` uses `tokio::select!` on spawned task handles; the losing task's handle is dropped but the task may still run, causing data loss on half-close.
- **#004** — `thread::sleep(1ms)` inside the sniffer loop blocks all in-flight connections during injection.
- **#007** — If the sniffer thread panics, handlers silently wait until their 2 s timeout with no indication of the root cause.
- **#021** — Linux `send_frame` hardcodes `ETH_P_IP`; IPv6 injection will silently fail.
