# Issue 020: `Ordering::Relaxed` for the stop flag — may miss signal on ARM

**Severity:** Code Smell  
**Files:** `src/sniffer/mod.rs:203`, `src/shutdown.rs:30`

## Description

The stop flag uses `Relaxed` ordering for both store and load:

```rust
// shutdown.rs:30
stop.store(true, Ordering::Relaxed);

// sniffer/mod.rs:203
if stop.load(Ordering::Relaxed) {
```

On x86_64 this works because TSO (Total Store Order) guarantees visibility quickly. On ARM (Apple Silicon), a `Relaxed` store in one thread may not be visible to a `Relaxed` load in another thread for an unbounded time. The store becomes visible eventually, but the sniffer could run many additional loop iterations before seeing it.

## Impact

On ARM (macOS Apple Silicon), shutdown may be delayed by an unbounded number of sniffer loop iterations. In practice the 100ms recv timeout means the delay is likely under a second, but the code is formally incorrect for the intended semantics.

## Suggested Fix

Use `Release`/`Acquire` ordering to establish a happens-before relationship:

```rust
// shutdown.rs
stop.store(true, Ordering::Release);

// sniffer/mod.rs
if stop.load(Ordering::Acquire) {
```

Or use `SeqCst` for simplicity since this is not a hot path:

```rust
stop.store(true, Ordering::SeqCst);
// ...
if stop.load(Ordering::SeqCst) {
```
