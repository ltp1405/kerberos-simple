use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::server::{
    entry::Entry, errors::KrbInfraSvrResult, receiver::AsyncReceiver,
    utils::extract_bytes_or_delegate_to_router, ExchangeError,
};

pub struct TcpEntry<R: AsyncReceiver + 'static> {
    stream: TcpStream,
    receiver: R,
}

impl<R: AsyncReceiver> TcpEntry<R> {
    pub fn new(stream: TcpStream, receiver: R) -> Self {
        Self { stream, receiver }
    }
}

#[async_trait]
impl<R: AsyncReceiver> Entry for TcpEntry<R> {
    async fn handle(&mut self) -> KrbInfraSvrResult<()> {
        let bytes = {
            // Allocate 4 octets for the length of the message
            let mut buffer = [0u8; 4];

            // Read the length of the message
            self.stream.read_exact(&mut buffer).await?;

            // Convert to u32 and check for the highest bit (this bit must be set to 0 in the current implementation)
            let length = u32::from_be_bytes(buffer);

            if length & 0x80000000 != 0 {
                let result = self
                    .receiver
                    .error(ExchangeError::LengthPrefix { value: length });

                let response = extract_bytes_or_delegate_to_router(result)?;

                // Send the length of the message first
                let length = (response.len() as u32).to_be_bytes();
                self.stream.write_all(&length).await?;

                // Send the message
                self.stream.write_all(&response).await?;

                return Ok(());
            }

            // Allocate a buffer of the length of the message and read the message
            let mut buffer = vec![0; length as usize];

            self.stream.read_exact(&mut buffer).await?;

            buffer
        };

        let result = self.receiver.receive(&bytes).await;

        let response = extract_bytes_or_delegate_to_router(result)?;

        // Send the length of the message first
        let length = (response.len() as u32).to_be_bytes();
        self.stream.write_all(&length).await?;

        // Send the message
        self.stream.write_all(&response).await?;

        Ok(())
    }
}
