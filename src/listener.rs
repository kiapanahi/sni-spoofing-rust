use std::net::IpAddr;

use tokio::net::TcpListener;
use tracing::{error, info};

use crate::config::ListenerConfig;
use crate::handler;
use crate::proto::SnifferCommand;

pub async fn run_listener(
    lc: ListenerConfig,
    local_ip: IpAddr,
    cmd_tx: std::sync::mpsc::Sender<SnifferCommand>,
) {
    let listener = match TcpListener::bind(lc.listen).await {
        Ok(l) => {
            info!(listen = %lc.listen, upstream = %lc.connect, sni = %lc.fake_sni, "listener started");
            l
        }
        Err(e) => {
            error!(listen = %lc.listen, "failed to bind: {}", e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let upstream = lc.connect;
                let sni = lc.fake_sni.clone();
                let tx = cmd_tx.clone();
                let lip = local_ip;
                tokio::spawn(async move {
                    tracing::debug!(peer = %peer, "accepted connection");
                    handler::handle_connection(stream, upstream, sni, lip, tx).await;
                });
            }
            Err(e) => {
                error!("accept error: {}", e);
            }
        }
    }
}
