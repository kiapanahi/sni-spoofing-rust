# Issue 009: Crate-wide `#![allow(dead_code)]`

**Severity:** Code Smell  
**File:** `src/main.rs:1`

## Description

```rust
#![allow(dead_code)]
```

This suppresses dead code warnings for every module in the crate. It hides unused functions, struct fields, and enum variants. This is especially risky in multi-platform code where `#[cfg]` gates can silently make code unreachable on certain targets.

## Impact

Dead code accumulates without warning. Functions that are no longer called, struct fields that are never read, and enum variants that are never constructed all go undetected.

## Suggested Fix

Remove the crate-level allow:

```rust
// Delete: #![allow(dead_code)]
```

Add targeted `#[allow(dead_code)]` on specific items that are intentionally unused. For platform-specific code that's conditionally compiled, the `#[cfg]` attributes already handle visibility — if code is truly dead on all platforms, it should be removed.

After removing the blanket allow, run `cargo check` on each target platform to identify and address actual dead code.
