use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use super::{
    guard::{Guard, UdpSocketGuard},
    Server,
};

pub struct UdpServer(SocketAddr);

impl UdpServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

impl Server for UdpServer {
    type Proto = UdpSocketGuard;
    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(&self.0).await?;
        let mut guard = Self::Proto::new(socket);
        loop {
            guard.handle().await?;
        }
    }
}
