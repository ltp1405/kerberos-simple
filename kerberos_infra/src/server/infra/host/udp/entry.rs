use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::server::infra::{
    host::{entry::Entry, utils::extract_bytes_or_delegate_to_router, ExchangeError, HostResult},
    KrbAsyncReceiver, KrbCache, KrbDatabase,
};

pub struct UdpEntry<T> {
    socket: Arc<UdpSocket>,
    bytes: Vec<u8>,
    destination: SocketAddr,
    receiver: KrbAsyncReceiver<T>,
}

impl<T> UdpEntry<T> {
    const MAX_BUFFER_SIZE: usize = 1024; // 1KB

    pub fn new(
        socket: Arc<UdpSocket>,
        bytes: Vec<u8>,
        destination: SocketAddr,
        receiver: KrbAsyncReceiver<T>,
    ) -> Self {
        Self {
            socket,
            bytes,
            destination,
            receiver,
        }
    }
}

#[async_trait]
impl<T> Entry for UdpEntry<T> {
    type Db = T;

    async fn handle(&mut self, database: KrbDatabase<T>, cache: KrbCache) -> HostResult<()> {
        let receiver = self.receiver.read().await;

        let result = receiver.receive(&self.bytes, database, cache).await;

        let mut response = extract_bytes_or_delegate_to_router(result)?;

        if response.len() > Self::MAX_BUFFER_SIZE {
            let result = receiver.error(ExchangeError::UdpPacketOversize {
                maximum_length: Self::MAX_BUFFER_SIZE,
                length: response.len(),
            });

            response = extract_bytes_or_delegate_to_router(result)?;
        }

        self.socket.send_to(&response, &self.destination).await?;

        Ok(())
    }
}
