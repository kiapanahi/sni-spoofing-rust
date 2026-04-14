# Issue 013: TLS template hex decoded at runtime on every `build_client_hello` call

**Severity:** Code Smell  
**File:** `src/packet/tls.rs:9-11`

## Description

```rust
fn template_bytes() -> Vec<u8> {
    hex::decode(TPL_HEX).expect("invalid template hex")
}
```

`build_client_hello` calls `template_bytes()` on every invocation, re-parsing the ~1034-character hex string and allocating a new `Vec<u8>`. The data is a compile-time constant that never changes.

## Impact

Unnecessary allocation + parsing on every connection. Minor performance cost but egregious for a constant.

## Suggested Fix

**Option A** (preferred) — declare as a `const` byte array, eliminating runtime work entirely:

```rust
const TPL: &[u8] = &[
    0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
    // ... remaining bytes ...
];
```

Then derive the static slices as `const`:

```rust
const STATIC1: &[u8] = &TPL[..11];
const STATIC3: &[u8] = &TPL[76..120];
// etc.
```

**Option B** — use `LazyLock` for one-time initialization:

```rust
use std::sync::LazyLock;

static TPL: LazyLock<Vec<u8>> = LazyLock::new(|| hex::decode(TPL_HEX).unwrap());
```

Option A is preferred because it eliminates all runtime cost and makes the data available at compile time.
