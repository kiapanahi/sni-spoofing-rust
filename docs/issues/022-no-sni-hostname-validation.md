# Issue 022: No hostname validation for fake_sni config field

**Severity:** Code Smell  
**File:** `src/config.rs:26-29`

## Description

The config validation only checks SNI byte length:

```rust
if lc.fake_sni.len() > 219 {
    return Err(crate::error::ConfigError::SniTooLong(lc.fake_sni.clone()));
}
```

There's no validation that the SNI is a valid hostname. Values like `"hello world\n"`, `""`, `"---"`, or non-ASCII strings pass validation and produce a ClientHello with a malformed SNI. While the tool would still function (the DPI sees whatever bytes are in the extension), a clearly invalid hostname might cause the DPI to flag the connection as suspicious rather than whitelisting it.

## Impact

Misconfiguration goes undetected. An empty string or a string with spaces would produce a valid-looking TLS ClientHello with an obviously malformed SNI, potentially making the connection more suspicious to DPI rather than less.

## Suggested Fix

Add hostname validation:

```rust
fn is_valid_sni(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 219
        && s.is_ascii()
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}
```

Use in config validation:

```rust
for lc in &cfg.listeners {
    if !is_valid_sni(&lc.fake_sni) {
        return Err(crate::error::ConfigError::InvalidSni(lc.fake_sni.clone()));
    }
}
```

Add the error variant:

```rust
#[error("invalid fake_sni (must be a valid hostname, max 219 bytes): '{0}'")]
InvalidSni(String),
```
