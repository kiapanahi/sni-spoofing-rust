# Issue 019: No graceful cleanup of sniffer connections on shutdown

**Severity:** Code Smell  
**File:** `src/sniffer/mod.rs:203-206`

## Description

When shutdown is signaled, the sniffer exits without notifying active connections:

```rust
if stop.load(Ordering::Relaxed) {
    info!("sniffer thread stopping");
    return;  // all ConnState entries are dropped silently
}
```

Active connections' `result_tx` channels are dropped. The handlers will wait until their 2-second timeout fires, then report "timeout waiting for fake ACK" errors. Users see a burst of timeout errors during shutdown.

## Impact

Misleading error messages during shutdown. Connections that were mid-handshake get a timeout error instead of a clean "shutting down" notification.

## Suggested Fix

Drain and notify all active connections before returning:

```rust
if stop.load(Ordering::Acquire) {
    info!("sniffer thread stopping, notifying {} active connections", connections.len());
    for (_, conn) in connections.drain() {
        let _ = conn.result_tx.try_send(SnifferResult::Failed("shutting down".into()));
    }
    return;
}
```
