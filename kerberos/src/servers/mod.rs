use std::net::SocketAddr;
use std::time::{SystemTime, SystemTimeError};
use crate::client::Client;

pub struct Server {
    addr: SocketAddr,
}

impl Server {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn send(&self, bytes: Vec<u8>, destination: Client) -> tokio::io::Result<()> {
        todo!();
    }
    pub async fn receive(&self) -> tokio::io::Result<Vec<u8>> {
        todo!();
    }
}