use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

pub struct Client {
    addr: SocketAddr,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    

    pub async fn send_tickets(&self, ticket: &[u8]) -> tokio::io::Result<()> {
        let mut socket = TcpStream::connect(self.addr).await?;
        socket.write_all(ticket).await?;
        println!("Client sent: {}", String::from_utf8_lossy(ticket));
        Ok(())
    }

    pub async fn send_request_to_as(&self, request: &[u8]) -> tokio::io::Result<Vec<u8>> {
        let mut socket = TcpStream::connect(self.addr).await?;
        let mut buffer = vec![0; 1024];
        let n = socket.read(&mut buffer).await?;
        buffer.truncate(n);
        println!("Client received: {}", String::from_utf8_lossy(&buffer));
        Ok(buffer)
    }
    
    pub async fn send_cleartext_request_to_as(&self, cleartext_request: &str) -> tokio::io::Result<()> {
        todo!();
    }
}