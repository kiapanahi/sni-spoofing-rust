# Issue 016: `parse_sni` hardcodes byte offsets — only works on self-generated packets

**Severity:** Code Smell  
**File:** `src/packet/tls.rs:76-85`

## Description

```rust
pub fn parse_sni(client_hello: &[u8]) -> Option<String> {
    if client_hello.len() < CLIENT_HELLO_SIZE { return None; }
    let sni_len = u16::from_be_bytes([client_hello[125], client_hello[126]]) as usize;
    if 127 + sni_len > client_hello.len() { return None; }
    String::from_utf8(client_hello[127..127 + sni_len].to_vec()).ok()
}
```

This reads the SNI from hardcoded offsets 125-127, which only works for packets built by `build_client_hello` (specific cipher suite list length, specific extension ordering). A real captured ClientHello from Chrome, Firefox, or any other client would have different offsets, returning garbage or `None`.

The function name `parse_sni` suggests generality it doesn't have.

## Impact

Not a runtime bug since the function is only used in tests. But it's misleading and will break if anyone uses it for real ClientHello parsing (e.g., for logging the actual SNI of intercepted traffic).

## Suggested Fix

**Option A** — rename to clarify the constraint:

```rust
/// Parse SNI from a ClientHello built by `build_client_hello`.
/// Does NOT work on arbitrary ClientHello packets.
pub fn parse_template_sni(client_hello: &[u8]) -> Option<String> {
    // ...
}
```

**Option B** — implement proper TLS extension walking:

```rust
pub fn parse_sni(client_hello: &[u8]) -> Option<String> {
    if client_hello.len() < 5 { return None; }
    
    // Skip TLS record header (5 bytes) + handshake header (4 bytes)
    let mut pos = 9;
    // Skip client version (2) + random (32)
    pos += 34;
    if pos >= client_hello.len() { return None; }
    
    // Skip session_id
    let sess_len = client_hello[pos] as usize;
    pos += 1 + sess_len;
    if pos + 2 > client_hello.len() { return None; }
    
    // Skip cipher_suites
    let cs_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= client_hello.len() { return None; }
    
    // Skip compression_methods
    let comp_len = client_hello[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > client_hello.len() { return None; }
    
    // Extensions
    let ext_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([client_hello[pos + 2], client_hello[pos + 3]]) as usize;
        pos += 4;
        
        if ext_type == 0x0000 {  // server_name
            // SNI list: 2 bytes list_len + 1 byte name_type + 2 bytes name_len + name
            if pos + 5 <= pos + ext_data_len {
                let name_len = u16::from_be_bytes([client_hello[pos + 3], client_hello[pos + 4]]) as usize;
                if pos + 5 + name_len <= client_hello.len() {
                    return String::from_utf8(client_hello[pos + 5..pos + 5 + name_len].to_vec()).ok();
                }
            }
            return None;
        }
        pos += ext_data_len;
    }
    None
}
```
