use std::net::SocketAddr;

use tokio::net::TcpListener;

use crate::server::{entry::Entry, errors::KrbInfraResult, receiver::AsyncReceiver};

use super::entry::TcpEntry;

pub struct Router<A: AsyncReceiver> {
    addr: SocketAddr,
    receiver: A,
}

impl<A: AsyncReceiver> From<(SocketAddr, A)> for Router<A> {
    fn from((addr, receiver): (SocketAddr, A)) -> Self {
        Self { addr, receiver }
    }
}

unsafe impl<A> Send for Router<A> where A: AsyncReceiver {}

impl<A: AsyncReceiver + 'static> Router<A> {
    pub async fn listen(&self) -> KrbInfraResult<()> {
        let listener = TcpListener::bind(&self.addr).await?;

        loop {
            let (stream, _) = listener.accept().await?;

            tokio::spawn({
                let mut entry = TcpEntry::new(stream, self.receiver);
                async move { entry.handle().await }
            });
        }
    }
}
