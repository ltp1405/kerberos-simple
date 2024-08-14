use std::{error::Error, net::SocketAddr, vec};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    stream,
};

#[async_trait]
pub trait Guard {
    async fn handle(&mut self) -> Result<(), Box<dyn Error>>;
    async fn close(&mut self) -> Result<(), Box<dyn Error>>;
}

pub struct TcpStreamGuard(TcpStream);
pub struct UdpSocketGuard(UdpSocket);

impl TcpStreamGuard {
    pub fn new(stream: TcpStream) -> Self {
        Self(stream)
    }
}
#[async_trait]
impl Guard for TcpStreamGuard {
    async fn handle(&mut self) -> Result<(), Box<dyn Error>> {
        let mut buffer = vec![0; 1024];
        self.0.read(&mut buffer).await?;
        self.0.write_all(&buffer).await?;
        Ok(())
    }
    async fn close(&mut self) -> Result<(), Box<dyn Error>> {
        self.0.shutdown().await?;
        Ok(())
    }
}

impl UdpSocketGuard {
    pub fn new(socket: UdpSocket) -> Self {
        Self(socket)
    }
}
#[async_trait]
impl Guard for UdpSocketGuard {
    async fn handle(&mut self) -> Result<(), Box<dyn Error>> {
        let mut buffer = vec![0; 1024];
        let (_, addr) = self.0.recv_from(&mut buffer).await?;
        self.0.send_to(&buffer, addr).await?;
        Ok(())
    }
    async fn close(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
