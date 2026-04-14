# Issue 005: Fragile sync/async bridge — `blocking_send` panics inside tokio context

**Severity:** Design Issue  
**File:** `src/sniffer/mod.rs:304, 333`

## Description

`tokio::sync::mpsc::Sender::blocking_send()` panics if called from within a tokio runtime. Currently safe because the sniffer runs on a bare `std::thread`, but this is undocumented and fragile.

```rust
// sniffer/mod.rs:333
let _ = conn.result_tx.blocking_send(SnifferResult::FakeConfirmed);
```

If the sniffer is ever refactored to run inside tokio (e.g., via `spawn_blocking`), it silently becomes a panic bomb.

The overall channel topology is also mixed:
- Command channel: `std::sync::mpsc` (handler -> sniffer)
- Result channel: `tokio::sync::mpsc` (sniffer -> handler)
- Registration ack: `tokio::sync::oneshot` (sniffer -> handler)

## Impact

Not a current bug, but a maintenance trap. Any future refactoring that moves the sniffer into tokio context causes a panic at runtime.

## Suggested Fix

**Option A** — use `try_send()` instead (non-blocking, appropriate for a channel with capacity 4):

```rust
let _ = conn.result_tx.try_send(SnifferResult::FakeConfirmed);
```

**Option B** — use `std::sync::mpsc` or crossbeam for the result channel, which has no runtime restrictions:

```rust
// proto.rs
pub struct Registration {
    pub result_tx: std::sync::mpsc::Sender<SnifferResult>,
    // ...
}
```

Then in the handler, wrap the blocking receiver in `tokio::task::spawn_blocking` or poll it with a `tokio::sync::watch`.

**Option C** — document the constraint clearly:

```rust
// INVARIANT: This function must be called from a bare std::thread,
// never from within a tokio runtime context, because it uses
// tokio::sync::mpsc::Sender::blocking_send().
pub fn run_sniffer(...) { ... }
```
