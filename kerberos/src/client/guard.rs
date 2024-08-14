use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

#[async_trait]
pub trait ClientGuard {
    async fn handle(
        &mut self,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn Error>>;
    async fn close(&mut self) -> Result<(), Box<dyn Error>>;
}

pub struct TcpClientGuard(Option<TcpStream>);
pub struct UdpClientGuard(UdpSocket);

// TCP stream guard
impl TcpClientGuard {
    pub fn new() -> Self {
        Self(None)
    }
    pub fn set_stream(&mut self, stream: TcpStream) {
        self.0 = Some(stream);
    }
}
#[async_trait]
impl ClientGuard for TcpClientGuard {
    async fn handle(
        &mut self,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if let Some(ref mut stream) = self.0 {
            stream.write_all(bytes).await?;
            let mut buf = vec![0; 1024];
            let n = stream.read(&mut buf).await?;
            buf.truncate(n);
            Ok(buf)
        } else {
            let mut stream = TcpStream::connect(destination).await?;
            stream.write_all(bytes).await?;
            let mut buf = vec![0; 1024];
            let n = stream.read(&mut buf).await?;
            buf.truncate(n);
            self.set_stream(stream);
            Ok(buf)
        }
    }
    async fn close(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(ref mut stream) = self.0.take() {
            stream.shutdown().await?;
        }
        Ok(())
    }
}

// UDP socket guard
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
impl ClientGuard for UdpClientGuard {
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
