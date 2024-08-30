use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::server::{
    entry::Entry,
    errors::KrbInfraSvrResult,
    receiver::AsyncReceiver,
    utils::{extract_bytes_or_delegate_to_router, TagLengthStreamReader},
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
            let (mut incoming_buffer, mut buffer) = TagLengthStreamReader::from(&mut self.stream)
                .try_into()
                .await?;

            // Read the message
            self.stream.read_exact(&mut incoming_buffer).await?;

            buffer.extend_from_slice(&incoming_buffer);

            buffer
        };

        let response = extract_bytes_or_delegate_to_router(self.receiver.receive(&bytes).await)?;

        // Send the message
        self.stream.write_all(&response).await?;

        Ok(())
    }
}
