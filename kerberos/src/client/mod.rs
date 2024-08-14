use std::{error::Error, net::SocketAddr};

use guard::{ClientGuard, TcpClientGuard, UdpClientGuard};
use tokio::net::TcpStream;
mod guard;
pub enum Client {
    Tcp { addr: SocketAddr },
    Udp { addr: SocketAddr },
}

impl Client {
    pub fn new_tcp(addr: SocketAddr) -> Self {
        Client::Tcp { addr }
    }

    pub fn new_udp(addr: SocketAddr) -> Self {
        Client::Udp { addr }
    }

    pub async fn send_and_receive(
        &self,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            Client::Tcp { addr } => {
                let mut guard = TcpClientGuard::new();
                guard.handle(bytes, destination).await
            }
            Client::Udp { addr } => {
                let mut guard = UdpClientGuard::new(addr.clone()).await;
                guard.handle(bytes, destination).await
            }
        }
    }
}
