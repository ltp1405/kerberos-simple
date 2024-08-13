use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::UdpSocket;

use super::Transporter;

pub struct UdpTransporter {
    socket: Option<UdpSocket>,
}

#[async_trait]
impl Transporter for UdpTransporter {
    async fn new(addr: SocketAddr) -> Self {
        return Self {
            socket: Some(UdpSocket::bind(addr).await.expect("Unable to bind to udp")),
        };
    }
    async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(_socket) = &self.socket {
            loop {}
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No socket",
            )));
        }
    }
    async fn connect(&mut self, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
        if let Some(socket) = &self.socket {
            socket
                .connect(addr)
                .await
                .expect("Unable to connect to udp");
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
            socket.send(buf).await.expect("Unable to send to udp");
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
            socket.recv(buf).await.expect("Unable to receive from udp");
            Ok(())
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No socket",
            )));
        }
    }
}
