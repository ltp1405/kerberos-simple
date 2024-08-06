use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

pub struct Client {
    addr: SocketAddr,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn send_request_access_to_server(&self) -> tokio::io::Result<()> {
        todo!();
    }

    pub async fn send_request_for_ticket(&self, request: &[u8]) -> tokio::io::Result<()> {
        todo!();
    }
    
    pub async fn send_request_for_tgt(&self) -> tokio::io::Result<()> {
        todo!();
    }
}