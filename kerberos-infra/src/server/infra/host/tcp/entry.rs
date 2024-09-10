use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::server::infra::{
    host::{
        entry::Entry,
        utils::{extract_bytes_or_delegate_to_router, TagLengthStreamReader},
        AsyncReceiver, KrbInfraSvrResult,
    },
    DataBox, KrbCache, KrbDatabase,
};

pub struct TcpEntry {
    stream: TcpStream,
    receiver: DataBox<dyn AsyncReceiver>,
}

impl TcpEntry {
    pub fn new(stream: TcpStream, receiver: DataBox<dyn AsyncReceiver>) -> Self {
        Self { stream, receiver }
    }
}

#[async_trait]
impl Entry for TcpEntry {
    async fn handle(
        &mut self,
        database: KrbDatabase,
        cache: KrbCache,
    ) -> KrbInfraSvrResult<()> {
        let bytes = {
            let (mut incoming_buffer, mut buffer) = TagLengthStreamReader::from(&mut self.stream)
                .try_into()
                .await?;

            // Read the message
            self.stream.read_exact(&mut incoming_buffer).await?;

            buffer.extend_from_slice(&incoming_buffer);

            buffer
        };

        let response = extract_bytes_or_delegate_to_router({
            let lock = self.receiver.read().await;
            lock.receive(&bytes, database, cache).await
        })?;

        // Send the message
        self.stream.write_all(&response).await?;

        Ok(())
    }
}
