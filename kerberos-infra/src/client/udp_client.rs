use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;

use super::{guard::Guard, udp_client_guard::UdpClientGuard, Client};

pub struct UdpClient {
    addr: SocketAddr,
    guard: UdpClientGuard,
}

impl UdpClient {
    pub async fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            guard: UdpClientGuard::new(addr).await,
        }
    }
}

#[async_trait]
impl Client for UdpClient {
    async fn send_and_receive(
        &mut self,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.guard.handle(bytes, destination).await
    }
    async fn close(&mut self) -> Result<(), Box<dyn Error>> {
        self.guard.close().await
    }
}
