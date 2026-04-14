# Issue 012: `assert!` / `expect` in non-test code instead of `Result`

**Severity:** Code Smell  
**Files:** `src/packet/tls.rs:28,72`, `src/main.rs:105`, `src/sniffer/linux.rs:19`, `src/sniffer/macos.rs:41`

## Description

Multiple `assert!` and `expect` calls in library/non-test code will panic at runtime on invalid input instead of returning errors that callers can handle.

```rust
// tls.rs:28
assert!(sni.len() <= 219, "SNI too long (max 219 bytes)");

// tls.rs:72
assert_eq!(out.len(), CLIENT_HELLO_SIZE, "ClientHello size mismatch: got {}", out.len());

// main.rs:105
.expect("failed to create tokio runtime");

// linux.rs:19 and macos.rs:41
let first = upstreams.first().expect("no upstreams");
```

The config validation at `config.rs:26-29` already checks SNI length, but if anyone calls `build_client_hello` from a different path, it panics.

## Suggested Fix

For `build_client_hello`, return `Result`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("SNI too long ({0} bytes, max 219)")]
    SniTooLong(usize),
}

pub fn build_client_hello(sni: &str) -> Result<Vec<u8>, TlsError> {
    if sni.len() > 219 {
        return Err(TlsError::SniTooLong(sni.len()));
    }
    // ...construction logic...
    debug_assert_eq!(out.len(), CLIENT_HELLO_SIZE); // keep as debug_assert
    Ok(out)
}
```

For the `expect("no upstreams")` calls, accept a checked non-empty type or validate at the call site:

```rust
pub fn open(upstreams: &[SocketAddr]) -> Result<Self, SnifferError> {
    let first = upstreams.first()
        .ok_or_else(|| SnifferError::Other("no upstreams configured".into()))?;
    // ...
}
```
