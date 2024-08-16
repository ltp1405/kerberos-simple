use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::UdpSocket;

use super::guard::Guard;

pub struct UdpClientGuard(UdpSocket);


impl UdpClientGuard {
    pub async fn new(addr: SocketAddr) -> Self {
        Self(
            UdpSocket::bind(addr)
                .await
                .expect("Failed to bind UDP socket"),
        )
    }
}
#[async_trait]
impl Guard for UdpClientGuard {
    async fn handle(
        &mut self,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.0.send_to(bytes, &destination).await?;
        let mut buf = vec![0; 1024];
        let (n, _) = self.0.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }
    async fn close(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
