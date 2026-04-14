# Issue 021: Linux `send_frame` hardcodes ETH_P_IP even for IPv6 packets

**Severity:** Code Smell  
**File:** `src/sniffer/linux.rs:93`

## Description

```rust
sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
```

When injecting a frame for an IPv6 connection, `sockaddr_ll.sll_protocol` is hardcoded to `ETH_P_IP` (0x0800). It should be `ETH_P_IPV6` (0x86DD) for IPv6 frames. The ethertype in the Ethernet header itself would be correct (copied from the template), but `sll_protocol` tells the kernel what protocol to expect.

## Impact

IPv6 fake packets may be misrouted or dropped by the kernel's link-layer processing. IPv4 connections are unaffected.

## Suggested Fix

Detect the IP version from the frame's ethertype and set the protocol accordingly:

```rust
fn send_frame(&mut self, frame: &[u8]) -> Result<(), SnifferError> {
    let protocol = if frame.len() >= 14 {
        u16::from_be_bytes([frame[12], frame[13]])  // ethertype from Ethernet header
    } else {
        libc::ETH_P_IP as u16
    };

    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = protocol.to_be();
    sll.sll_ifindex = self.ifindex;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&frame[0..6]);

    let ret = unsafe {
        libc::sendto(
            self.fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if ret < 0 {
        return Err(SnifferError::Inject(io::Error::last_os_error()));
    }
    Ok(())
}
```
