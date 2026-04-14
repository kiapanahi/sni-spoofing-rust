# Issue 002: Connection state leaks in sniffer when handler times out

**Severity:** Bug  
**File:** `src/handler.rs:156-159`

## Description

When the 2-second fake-confirmation timeout fires, the handler returns `Err(HandlerError::Timeout)` without sending a `SnifferCommand::Deregister`. The `ConnState` entry remains in the sniffer's `connections` HashMap forever, processing packets for a dead connection.

```rust
// handler.rs:156-159
match confirmed {
    Ok(Ok(())) => {}
    Ok(Err(e)) => return Err(e),
    Err(_) => return Err(HandlerError::Timeout), // no Deregister sent
}
```

Compare with the connect-failure path at line 104 which correctly sends Deregister.

## Impact

Slow memory leak. Each timed-out connection leaves a `ConnState` in the sniffer map permanently. On a long-running instance with intermittent connectivity issues, this accumulates. The sniffer also wastes cycles processing packets for dead connections.

## Suggested Fix

**Option A** — send Deregister in the error paths:

```rust
match confirmed {
    Ok(Ok(())) => {}
    Ok(Err(e)) => {
        let _ = cmd_tx.send(SnifferCommand::Deregister(Deregistration { conn_id }));
        return Err(e);
    }
    Err(_) => {
        let _ = cmd_tx.send(SnifferCommand::Deregister(Deregistration { conn_id }));
        return Err(HandlerError::Timeout);
    }
}
```

**Option B** (preferred) — use a RAII guard that sends Deregister on drop unless disarmed:

```rust
struct DeregisterGuard<'a> {
    conn_id: ConnId,
    cmd_tx: &'a std::sync::mpsc::Sender<SnifferCommand>,
    disarmed: bool,
}

impl Drop for DeregisterGuard<'_> {
    fn drop(&mut self) {
        if !self.disarmed {
            let _ = self.cmd_tx.send(SnifferCommand::Deregister(Deregistration {
                conn_id: self.conn_id,
            }));
        }
    }
}
```

Create it right after registration, disarm only on the success path. This guarantees cleanup regardless of how the function exits.
