# Issue 010: `unsafe` blocks without SAFETY comments

**Severity:** Code Smell  
**Files:** `src/sniffer/linux.rs` (8 blocks), `src/sniffer/macos.rs` (10 blocks), `src/sniffer/windows.rs` (1 block)

## Description

Rust convention (and clippy lint `clippy::undocumented_unsafe_blocks`) requires every `unsafe` block to have a `// SAFETY:` comment explaining why the invariants are upheld. None of the ~19 unsafe blocks in the codebase have safety comments.

Example from `linux.rs:22-28`:

```rust
let fd = unsafe {
    libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32)
};
```

## Impact

Makes it harder to audit safety. Without documented invariants, it's unclear whether each unsafe block is sound, and future modifications may accidentally violate unstated assumptions.

## Suggested Fix

Add `// SAFETY:` comments to each block. Examples:

```rust
// SAFETY: libc::socket with valid domain/type/protocol constants.
// Returns -1 on failure (checked below), valid fd on success.
let fd = unsafe {
    libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32)
};

// SAFETY: fd is a valid open file descriptor (checked at creation).
// sll is a zeroed and properly initialized sockaddr_ll structure.
// The buffer size is passed correctly as the sockaddr size.
let ret = unsafe {
    libc::bind(fd, &sll as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_ll>() as u32)
};

// SAFETY: fd is valid, buf points to a valid mutable buffer of buf.len() bytes.
// recvfrom with null src_addr/addrlen is allowed per POSIX.
let n = unsafe {
    libc::recvfrom(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
};
```

Consider enabling the clippy lint to enforce this going forward:

```rust
#![warn(clippy::undocumented_unsafe_blocks)]
```
