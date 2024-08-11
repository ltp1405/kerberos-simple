use std::net::SocketAddr;

use crate::servers::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Client {
    addr: SocketAddr,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
    pub async fn send(&self, bytes: Vec<u8>, destination: Server) -> tokio::io::Result<()> {
        todo!();
    }
    pub async fn receive(&self) -> tokio::io::Result<Vec<u8>> {
        todo!();
    }
}
