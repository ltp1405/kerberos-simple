use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::Transport;

pub struct TcpTransport {
    addr: SocketAddr,
    stream: Option<TcpStream>,
}

impl TcpTransport {
    pub fn new(addr: SocketAddr) -> Self {
        return Self { addr, stream: None };
    }
}
#[async_trait]
impl Transport for TcpTransport {
    async fn new_transport(addr: SocketAddr) -> Self {
        return Self { addr, stream: None };
    }
    async fn connect(&mut self, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
        self.stream = Some(
            TcpStream::connect(addr)
                .await
                .expect("Unable to connect to tcp"),
        );
        Ok(())
    }
    async fn write(&mut self, buf: &[u8]) -> Result<(), Box<dyn Error>> {
        if let Some(ref mut stream) = self.stream {
            stream.write_all(buf);
            Ok(())
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No stream",
            )));
        }
    }
    async fn read(&mut self, buf: &mut [u8]) -> Result<(), Box<dyn Error>> {
        if let Some(ref mut stream) = self.stream {
            stream.read_to_end(buf.to_vec().as_mut()).await?;
            Ok(())
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No stream",
            )));
        }
    }
}
