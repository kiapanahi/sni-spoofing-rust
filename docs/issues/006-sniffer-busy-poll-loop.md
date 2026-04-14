# Issue 006: Sniffer busy-polls with 100ms granularity

**Severity:** Design Issue  
**File:** `src/sniffer/mod.rs:202-254`

## Description

The main sniffer loop does:

1. `try_recv` commands (non-blocking) — drains all pending commands
2. `recv_frame` (blocks up to 100ms timeout) — waits for a packet
3. Process the packet
4. Repeat

When there are no packets AND no commands, this loops: `try_recv` returns `Empty`, `recv_frame` times out after 100ms, repeat. This means:

- Registration commands sit in the channel for up to 100ms before being processed, adding latency to every new connection
- CPU never truly sleeps (wakes every 100ms to check)

## Impact

Each new connection has up to 100ms added latency before the sniffer starts monitoring its handshake. On a busy machine, this adds up. CPU usage is slightly elevated even when idle.

## Suggested Fix

Use `poll(2)` / `kevent` / `WaitForMultipleObjects` to wait on both the raw socket fd and a notification pipe triggered by new commands:

```rust
// Create a notification pipe
let (notify_write, notify_read) = pipe();

// In the command sender (handler side), after sending a command:
cmd_tx.send(cmd)?;
write(notify_write, &[1]); // wake the sniffer

// In the sniffer loop:
let mut poll_fds = [
    libc::pollfd { fd: backend.raw_fd(), events: libc::POLLIN, revents: 0 },
    libc::pollfd { fd: notify_read, events: libc::POLLIN, revents: 0 },
];
libc::poll(poll_fds.as_mut_ptr(), 2, -1); // block until either is ready

if poll_fds[1].revents & libc::POLLIN != 0 {
    // drain notification pipe
    read(notify_read, &mut [0; 64]);
    // process commands
}
if poll_fds[0].revents & libc::POLLIN != 0 {
    // recv and process packet
}
```

This would require `RawBackend` to expose its underlying fd via a `fn raw_fd(&self) -> RawFd` method.
