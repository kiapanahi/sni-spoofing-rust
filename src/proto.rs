use std::net::IpAddr;

use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug)]
pub enum SnifferResult {
    FakeConfirmed,
    Failed(String),
}

pub struct Registration {
    pub conn_id: ConnId,
    pub fake_payload: Vec<u8>,
    pub result_tx: mpsc::Sender<SnifferResult>,
    pub registered_tx: tokio::sync::oneshot::Sender<()>,
}

pub struct Deregistration {
    pub conn_id: ConnId,
}

pub enum SnifferCommand {
    Register(Registration),
    Deregister(Deregistration),
}
