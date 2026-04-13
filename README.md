# sni-spoof-rs

Rust implementation of [patterniha's SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) DPI bypass technique. All credit for the original idea and method goes to [@patterniha](https://github.com/patterniha).

A TCP forwarder that injects a fake TLS ClientHello with an intentionally wrong TCP sequence number right after the 3-way handshake. Stateful DPI reads the fake SNI and whitelists the flow. The real server drops the packet (out-of-window seq). Real traffic then passes through undetected.

## Platforms

- **Linux** -- AF_PACKET raw sockets. Requires root or `CAP_NET_RAW`.
- **macOS** -- BPF device. Requires root.

## Build

```
cargo build --release
```

Pre-built binaries for Linux (amd64/arm64) and macOS (amd64/arm64) are available on the [releases](https://github.com/therealaleph/sni-spoof-rs/releases) page.

## Usage

```
sudo ./sni-spoof-rs config.json
```

### config.json

```json
{
  "listeners": [
    {
      "listen": "0.0.0.0:40443",
      "connect": "104.18.4.130:443",
      "fake_sni": "security.vercel.com"
    }
  ]
}
```

| Field | Description |
|---|---|
| `listen` | Local address to accept connections on |
| `connect` | Upstream server IP and port (must be an IP, not a hostname) |
| `fake_sni` | SNI to put in the fake ClientHello (max 219 bytes) |

Multiple listeners are supported -- each maps to one upstream.

### With xray/v2ray

Point your VLESS/VMess client at `127.0.0.1:<listen_port>` instead of the real server. The tool handles the DPI bypass transparently. Your client's real TLS handshake passes through untouched after the fake injection.

### Logging

Set `RUST_LOG` for verbosity:

```
sudo RUST_LOG=debug ./sni-spoof-rs config.json
```

## How it works

1. Client connects to the listener, tool dials the upstream, kernel does the TCP 3-way handshake normally.
2. A raw packet sniffer captures the outbound SYN (records ISN) and the 3rd-handshake ACK.
3. After the 3rd ACK, a fake TLS ClientHello is injected with `seq = ISN + 1 - len(fake)`. This sequence number is before the server's receive window.
4. DPI parses the fake packet, sees an allowed SNI, and whitelists the connection.
5. The server drops the fake packet (out-of-window).
6. Tool waits for the server's ACK with `ack == ISN + 1` confirming the fake was ignored.
7. Bidirectional relay starts. The real TLS handshake and all subsequent traffic flow normally.

## License

MIT
