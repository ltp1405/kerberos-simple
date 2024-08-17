use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::client::{entry::Entry, KrbInfraCltResult};

pub struct TcpEntry<'a>(&'a mut TcpStream);

impl<'a> From<&'a mut TcpStream> for TcpEntry<'a> {
    fn from(stream: &'a mut TcpStream) -> Self {
        Self(stream)
    }
}

#[async_trait]
impl<'a> Entry for TcpEntry<'a> {
    async fn handle(&mut self, bytes: &[u8]) -> KrbInfraCltResult<Vec<u8>> {
        // For TCP, the length of the message is sent as a 4-octet big-endian unsigned integer
        // before the message itself
        let length_prefix_buffer = (bytes.len() as u32).to_be_bytes();
        self.0.write_all(&length_prefix_buffer).await?;

        // Send the message itself
        self.0.write_all(bytes).await?;

        // Read the length of the response
        let mut buffer = [0u8; 4];
        self.0.read_exact(&mut buffer).await?;
        let length = u32::from_be_bytes(buffer) as usize;

        // Allocate a buffer of the length of the response and read the response
        let mut buffer = vec![0; length];
        self.0.read_exact(&mut buffer).await?;

        Ok(buffer)
    }
}
