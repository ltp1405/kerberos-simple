use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::client::{entry::Entry, utils::TagLengthStreamReader, KrbInfraCltResult};

pub struct TcpEntry<'a>(&'a mut TcpStream);

impl<'a> From<&'a mut TcpStream> for TcpEntry<'a> {
    fn from(stream: &'a mut TcpStream) -> Self {
        Self(stream)
    }
}

#[async_trait]
impl<'a> Entry for TcpEntry<'a> {
    async fn handle(&mut self, bytes: &[u8]) -> KrbInfraCltResult<Vec<u8>> {
        // Send the message
        self.0.write_all(bytes).await?;

        // Read the length of the response
        let (mut incoming_buffer, mut buffer) =
            TagLengthStreamReader::from(&mut self.0).try_into().await?;

        // Read the response
        self.0.read_exact(&mut incoming_buffer).await?;
        
        // Extend the buffer with the incoming buffer
        buffer.extend_from_slice(&incoming_buffer);

        Ok(buffer)
    }
}
