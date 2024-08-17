use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::server::{entry::Entry, errors::KrbInfraResult, receiver::AsyncReceiver};

use super::entry::UdpEntry;

pub struct UdpRouter<A: AsyncReceiver> {
    addr: SocketAddr,
    receiver: A,
}

impl<A: AsyncReceiver> From<(SocketAddr, A)> for UdpRouter<A> {
    fn from((addr, receiver): (SocketAddr, A)) -> Self {
        Self { addr, receiver }
    }
}

unsafe impl<A> Send for UdpRouter<A> where A: AsyncReceiver {}

impl<A: AsyncReceiver + 'static> UdpRouter<A> {
    pub async fn listen(&self) -> KrbInfraResult<()> {
        let listener = UdpSocket::bind(&self.addr).await?;

        let mut entry = UdpEntry::new(listener, self.receiver);

        loop {
            entry.handle().await?;
        }
    }
}
