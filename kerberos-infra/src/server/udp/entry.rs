use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::server::{entry::Entry, errors::KrbInfraResult, receiver::AsyncReceiver};

pub struct UdpEntry<A: AsyncReceiver> {
    socket: UdpSocket,
    receiver: A,
}

impl<A: AsyncReceiver> UdpEntry<A> {
    pub fn new(socket: UdpSocket, receiver: A) -> Self {
        Self { socket, receiver }
    }
}

#[async_trait]
impl<A: AsyncReceiver> Entry for UdpEntry<A> {
    async fn handle(&mut self) -> KrbInfraResult<()> {
        let mut buffer = vec![0; 1024];
        
        let (len, addr) = self.socket.recv_from(&mut buffer).await?;
        
        buffer.truncate(len);
        
        self.socket.send_to(&buffer, addr).await?;
        
        Ok(())
    }
}
