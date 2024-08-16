use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;

use super::{guard::Guard, tcp_client_guard::TcpClientGuard, Client};

pub struct TcpClient {
    addr: SocketAddr,
    guard: Option<TcpClientGuard>,
}

impl TcpClient {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            guard: None,
        }
    }
}

#[async_trait]
impl Client for TcpClient {
    async fn send_and_receive(
        &mut self,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if let Some(ref mut guard) = self.guard {
            guard.handle(bytes, destination).await
        } else {
            let mut guard = TcpClientGuard::new();
            let result = guard.handle(bytes, destination).await;
            self.guard = Some(guard);
            result
        }
    }
    async fn close(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(ref mut guard) = self.guard {
            guard.close().await
        } else {
            Ok(())
        }
    }
}