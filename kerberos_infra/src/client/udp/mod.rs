use std::net::SocketAddr;

use async_trait::async_trait;
use entry::UdpEntry;
use tokio::net::UdpSocket;

use super::{entry::Entry, KrbInfraCltResult, Sendable};

pub struct UdpClient {
    host: SocketAddr,
    destination: SocketAddr,
    reusable_socket: Option<UdpSocket>,
}

impl UdpClient {
    pub fn new(host: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            host,
            destination,
            reusable_socket: None,
        }
    }

    pub fn auto(url: &str, destination: SocketAddr) -> KrbInfraCltResult<Self> {
        let host = format!("{}:0", url).parse()?;
        Ok(Self::new(host, destination))
    }

    pub fn close(&mut self) {
        self.reusable_socket = None;
    }
}

#[async_trait]
impl Sendable for UdpClient {
    async fn send(&mut self, bytes: &[u8]) -> KrbInfraCltResult<Vec<u8>> {
        // If the stream is not available, create a new one
        let socket = match self.reusable_socket.take() {
            Some(socket) => socket,
            None => {
                let socket = UdpSocket::bind(&self.host).await?;
                socket.connect(&self.destination).await?;
                socket
            }
        };

        self.reusable_socket = Some(socket);

        let mut entry = {
            let socket = self.reusable_socket.as_mut().unwrap();
            UdpEntry::from(socket)
        };

        entry.handle(bytes).await
    }
}

mod entry;
