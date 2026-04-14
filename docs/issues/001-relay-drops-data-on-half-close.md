# Issue 001: Relay drops in-flight data on TCP half-close

**Severity:** Bug  
**File:** `src/relay.rs:11-26`

## Description

When one copy direction finishes (e.g., client sends FIN), `tokio::select!` drops the other spawned task's `JoinHandle`. The underlying task keeps running briefly but the function returns `Ok(())`, causing the caller to drop both socket halves. Data the server is still sending back is silently lost.

Additionally, the two `tokio::spawn` calls create detached tasks. Dropping the `JoinHandle` doesn't cancel them, so the losing task runs until it errors on the dropped socket.

```rust
// Current code
tokio::select! {
    r = c2u => { /* log */ }
    r = u2c => { /* log */ }
}
Ok(())
```

## Impact

Any connection where one side closes before the other has finished sending will lose data. This is common in HTTP responses where the client closes the request body before the server finishes sending the response.

## Suggested Fix

Replace with `copy_bidirectional`, which handles half-close correctly and doesn't spawn:

```rust
use tokio::io;
use tokio::net::TcpStream;

pub async fn relay(mut client: TcpStream, mut upstream: TcpStream) -> Result<(), std::io::Error> {
    let _ = io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}
```

Or use `select!` on raw futures (no `spawn`) and shut down the write half of the destination when one direction completes:

```rust
pub async fn relay(client: TcpStream, upstream: TcpStream) -> Result<(), std::io::Error> {
    let (mut cr, mut cw) = io::split(client);
    let (mut ur, mut uw) = io::split(upstream);

    tokio::select! {
        _ = io::copy(&mut cr, &mut uw) => {
            let _ = uw.shutdown().await;
            let _ = io::copy(&mut ur, &mut cw).await;
        }
        _ = io::copy(&mut ur, &mut cw) => {
            let _ = cw.shutdown().await;
            let _ = io::copy(&mut cr, &mut uw).await;
        }
    }
    Ok(())
}
```
