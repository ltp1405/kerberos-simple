use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::UdpSocket;

use super::Transporter;

pub struct UdpTransporter {
    socket: Option<UdpSocket>,
}

impl UdpTransporter {
    pub async fn new(addr: SocketAddr) -> Self {
        return Self {
            socket: Some(UdpSocket::bind(addr).await.expect("Unable to bind to udp")),
        };
    }
}

#[async_trait]
impl Transporter for UdpTransporter {
    async fn new_transporter(addr: SocketAddr) -> Self {
        return Self {
            socket: Some(UdpSocket::bind(addr).await.expect("Unable to bind to udp")),
        };
    }
    async fn connect(&mut self, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
        if let Some(socket) = &self.socket {
            socket.connect(addr);
            Ok(())
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No socket",
            )));
        }
    }
    async fn write(&mut self, buf: &[u8]) -> Result<(), Box<dyn Error>> {
        if let Some(socket) = &self.socket {
            socket.send(buf);
            Ok(())
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No socket",
            )));
        }
    }
    async fn read(&mut self, buf: &mut [u8]) -> Result<(), Box<dyn Error>> {
        if let Some(socket) = &self.socket {
            socket.recv(buf);
            Ok(())
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No socket",
            )));
        }
    }
}
