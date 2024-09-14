use std::net::SocketAddr;

use async_trait::async_trait;
use entry::TcpEntry;
use tokio::{io::AsyncWriteExt, net::TcpStream};

use super::{entry::Entry, KrbInfraCltResult, Sendable};

pub struct TcpClient {
    destination: SocketAddr,
    reusable_stream: Option<TcpStream>,
}

impl TcpClient {
    pub fn new(destination: SocketAddr) -> Self {
        Self {
            destination,
            reusable_stream: None,
        }
    }

    pub async fn close(&mut self) -> KrbInfraCltResult<()> {
        if let Some(mut stream) = self.reusable_stream.take() {
            stream.shutdown().await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Sendable for TcpClient {
    async fn send(&mut self, bytes: &[u8]) -> KrbInfraCltResult<Vec<u8>> {
        // If the stream is not available, create a new one
        let stream = match self.reusable_stream.take() {
            Some(stream) => stream,
            None => TcpStream::connect(&self.destination).await?,
        };

        self.reusable_stream = Some(stream);

        let mut entry = {
            let stream = self.reusable_stream.as_mut().unwrap();
            TcpEntry::from(stream)
        };

        entry.handle(bytes).await
    }
}

mod entry;
