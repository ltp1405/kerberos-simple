use std::net::SocketAddr;

use tokio::net::TcpListener;

use crate::server::{
    entry::Entry, errors::KrbInfraSvrResult, receiver::AsyncReceiver, utils::handle_result_at_router,
};

use super::entry::TcpEntry;

pub struct TcpRouter<A: AsyncReceiver> {
    addr: SocketAddr,
    receiver: A,
}

impl<A: AsyncReceiver> From<(SocketAddr, A)> for TcpRouter<A> {
    fn from((addr, receiver): (SocketAddr, A)) -> Self {
        Self { addr, receiver }
    }
}

unsafe impl<A> Send for TcpRouter<A> where A: AsyncReceiver {}

impl<A: AsyncReceiver + 'static> TcpRouter<A> {
    pub async fn listen(&self) -> KrbInfraSvrResult<()> {
        let listener = TcpListener::bind(&self.addr).await?;

        loop {
            let (stream, addr) = listener.accept().await?;

            tokio::spawn({
                let mut entry = TcpEntry::new(stream, self.receiver);
                
                async move {
                    let result = entry.handle().await;
                    
                    handle_result_at_router(addr, result)
                }
            });
        }
    }
}
