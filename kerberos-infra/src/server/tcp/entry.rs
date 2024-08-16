use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::server::{entry::Entry, errors::KrbInfraResult, receiver::AsyncReceiver};

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
    async fn handle(&mut self) -> KrbInfraResult<()> {
        let bytes = {
            let mut buffer = vec![0; 1024];
            let len = self.stream.read(&mut buffer).await?;
            buffer.truncate(len);
            buffer
        };

        let response = self.receiver.receive(&bytes).await.map_err(|e| e.into())?;

        self.stream.write_all(&response).await?;

        Ok(())
    }
}
