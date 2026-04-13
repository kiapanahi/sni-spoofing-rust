use tokio::io;
use tokio::net::TcpStream;

pub async fn relay(client: TcpStream, upstream: TcpStream) -> Result<(), std::io::Error> {
    let (mut cr, mut cw) = io::split(client);
    let (mut ur, mut uw) = io::split(upstream);

    let c2u = tokio::spawn(async move { io::copy(&mut cr, &mut uw).await });
    let u2c = tokio::spawn(async move { io::copy(&mut ur, &mut cw).await });

    tokio::select! {
        r = c2u => {
            match r {
                Ok(Ok(n)) => tracing::debug!(bytes = n, "client->upstream finished"),
                Ok(Err(e)) => tracing::debug!("client->upstream error: {}", e),
                Err(e) => tracing::debug!("client->upstream task panicked: {}", e),
            }
        }
        r = u2c => {
            match r {
                Ok(Ok(n)) => tracing::debug!(bytes = n, "upstream->client finished"),
                Ok(Err(e)) => tracing::debug!("upstream->client error: {}", e),
                Err(e) => tracing::debug!("upstream->client task panicked: {}", e),
            }
        }
    }

    Ok(())
}
