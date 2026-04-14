# Issue 007: Silent failure when sniffer thread dies

**Severity:** Design Issue  
**File:** `src/handler.rs:96`

## Description

```rust
let _ = registered_rx.await;
```

If the sniffer thread panics or the command channel drops, the oneshot `registered_rx` resolves to `Err(Canceled)`, which is silently discarded by `let _`. The handler proceeds to connect to the upstream, then waits 2 seconds for a confirmation that will never arrive. The user sees a mysterious "timeout waiting for fake ACK" error with no hint that the sniffer is dead.

## Impact

Misleading error messages when the sniffer crashes. Every new connection will timeout with the same unhelpful message instead of immediately reporting that the sniffer is down.

## Suggested Fix

Check the registration result and return a specific error:

```rust
registered_rx.await.map_err(|_| HandlerError::SnifferDead)?;
```

Add a new error variant:

```rust
// error.rs
#[derive(Debug, Error)]
pub enum HandlerError {
    // ...existing variants...
    #[error("sniffer thread is not responding")]
    SnifferDead,
}
```

Optionally, also check if the command channel is alive before attempting registration:

```rust
cmd_tx
    .send(SnifferCommand::Register(reg))
    .map_err(|_| HandlerError::SnifferDead)?;
```

This already happens implicitly (the current `.map_err(|_| HandlerError::Registration)?` fires), but `Registration` doesn't convey that the sniffer is dead.
