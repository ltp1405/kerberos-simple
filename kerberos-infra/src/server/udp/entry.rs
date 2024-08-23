use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::server::{
    entry::Entry, errors::KrbInfraSvrResult, receiver::AsyncReceiver,
    utils::extract_bytes_or_delegate_to_router, ExchangeError,
};

pub struct UdpEntry<A: AsyncReceiver> {
    socket: Arc<UdpSocket>,
    bytes: Vec<u8>,
    destination: SocketAddr,
    receiver: A,
}

impl<A: AsyncReceiver> UdpEntry<A> {
    const MAX_BUFFER_SIZE: usize = 1024; // 1KB

    pub fn new(
        socket: Arc<UdpSocket>,
        bytes: Vec<u8>,
        destination: SocketAddr,
        receiver: A,
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
impl<A: AsyncReceiver> Entry for UdpEntry<A> {
    async fn handle(&mut self) -> KrbInfraSvrResult<()> {
        let result = self.receiver.receive(&self.bytes).await;

        let mut response = extract_bytes_or_delegate_to_router(result)?;

        if response.len() > Self::MAX_BUFFER_SIZE {
            let result = self.receiver.error(ExchangeError::UdpPacketOversize {
                maximum_length: Self::MAX_BUFFER_SIZE,
                length: response.len(),
            });

            response = extract_bytes_or_delegate_to_router(result)?;
        }

        self.socket.send_to(&response, &self.destination).await?;

        Ok(())
    }
}
