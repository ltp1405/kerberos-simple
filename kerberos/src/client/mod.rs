use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use crate::servers::Server;

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