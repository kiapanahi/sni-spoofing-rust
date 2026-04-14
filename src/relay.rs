use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

pub async fn relay(mut client: TcpStream, mut upstream: TcpStream) -> Result<(), std::io::Error> {
    let (c2u, u2c) = copy_bidirectional(&mut client, &mut upstream).await?;
    tracing::debug!(c2u, u2c, "relay finished");
    Ok(())
}
