# Issue 014: Hand-rolled hex decoder module

**Severity:** Code Smell  
**File:** `src/packet/tls.rs:13-25`

## Description

A custom `hex::decode` function exists solely to decode the TLS template string:

```rust
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}
```

This is a one-use utility for decoding a compile-time constant.

## Suggested Fix

If Issue 013 is resolved by making the template a `const` byte array, this module can be deleted entirely — it has no other callers.

If runtime hex decoding is still needed for some reason, use the `hex` crate (`hex = "0.4"`, 290k downloads/day) which is well-tested, handles edge cases, and supports `no_std`.
