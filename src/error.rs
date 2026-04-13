use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file '{0}': {1}")]
    Io(String, std::io::Error),
    #[error("failed to parse config file '{0}': {1}")]
    Parse(String, serde_json::Error),
    #[error("config has no listeners")]
    Empty,
    #[error("fake_sni too long (max 219 bytes): '{0}'")]
    SniTooLong(String),
}

#[derive(Debug, Error)]
pub enum SnifferError {
    #[error("failed to open raw socket: {0}")]
    SocketOpen(std::io::Error),
    #[error("failed to bind raw socket: {0}")]
    SocketBind(std::io::Error),
    #[error("failed to attach BPF filter: {0}")]
    FilterAttach(std::io::Error),
    #[error("recv error: {0}")]
    Recv(std::io::Error),
    #[error("inject error: {0}")]
    Inject(std::io::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("connect failed: {0}")]
    Connect(std::io::Error),
    #[error("sniffer registration failed")]
    Registration,
    #[error("timeout waiting for fake ACK confirmation")]
    Timeout,
    #[error("sniffer reported failure: {0}")]
    SnifferFailed(String),
    #[error("relay error: {0}")]
    Relay(std::io::Error),
}
