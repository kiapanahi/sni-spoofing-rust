# Issue 004: `thread::sleep(1ms)` in sniffer blocks all monitored connections

**Severity:** Design Issue  
**File:** `src/sniffer/mod.rs:300`

## Description

The sniffer is a single thread processing all connections. When it hits the 3rd ACK for any connection, it calls `thread::sleep(Duration::from_millis(1))` which blocks packet processing for every other monitored connection.

```rust
conn.fake_injected = true;
let fake_frame = build_fake_frame(frame, isn, &conn.fake_payload, ...);
thread::sleep(Duration::from_millis(1));  // blocks the ENTIRE sniffer thread
if let Err(e) = backend.send_frame(&fake_frame) { ... }
```

If 50 connections hit their 3rd ACK in quick succession, each pays a cumulative delay. The Python version avoids this by spawning a dedicated thread per injection.

## Impact

Under load, connections experience increased latency for fake injection. In the worst case, the 2-second confirmation timeout in the handler fires because the sniffer was sleeping for other connections' injections.

## Suggested Fix

Spawn a short-lived thread for the delay + inject. This requires the send capability to be shareable. The cleanest approach is splitting `RawBackend` into a `Receiver` + `Sender` pair:

```rust
pub trait RawSender: Send + Sync + 'static {
    fn send_frame(&self, frame: &[u8]) -> Result<(), SnifferError>;
}
```

Then in the sniffer loop:

```rust
let sender = backend.sender(); // Arc<dyn RawSender>
let fake_frame = build_fake_frame(...);
std::thread::spawn(move || {
    std::thread::sleep(Duration::from_millis(1));
    if let Err(e) = sender.send_frame(&fake_frame) {
        // log error
    }
});
```

For AF_PACKET on Linux and BPF on macOS, the fd can be `dup()`'d to create independent send handles. For WinDivert, the inject handle is already separate.
