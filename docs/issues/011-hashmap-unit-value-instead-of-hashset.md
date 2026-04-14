# Issue 011: `HashMap<(IpAddr, u16), ()>` should be `HashSet`

**Severity:** Code Smell  
**File:** `src/sniffer/mod.rs:191-192`

## Description

```rust
let upstream_set: HashMap<(IpAddr, u16), ()> =
    upstream_addrs.iter().map(|a| (*a, ())).collect();
```

This is a `HashSet` pretending to be a `HashMap`. The `()` value carries no information. Lookups use `.contains_key()` (`mod.rs:154-155`) when `.contains()` is the idiomatic method.

## Suggested Fix

```rust
use std::collections::HashSet;

let upstream_set: HashSet<(IpAddr, u16)> = upstream_addrs.iter().copied().collect();
```

Update call sites:

```rust
// Before:
let dst_is_upstream = upstream_addrs.contains_key(&(dst_ip, dport));

// After:
let dst_is_upstream = upstream_set.contains(&(dst_ip, dport));
```
