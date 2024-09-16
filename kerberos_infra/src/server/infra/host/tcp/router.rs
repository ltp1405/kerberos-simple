use std::net::SocketAddr;

use tokio::net::TcpListener;

use crate::server::infra::{
    host::{entry::Entry, utils::handle_result_at_router, HostResult},
    KrbAsyncReceiver, KrbCache, KrbDatabase,
};

use super::entry::TcpEntry;

pub struct TcpRouter<T> {
    addr: SocketAddr,
    receiver: KrbAsyncReceiver<T>,
}

impl<T> TcpRouter<T> {
    pub fn new(addr: SocketAddr, receiver: KrbAsyncReceiver<T>) -> Self {
        Self { addr, receiver }
    }
}

unsafe impl<T> Send for TcpRouter<T> {}

impl<T: 'static> TcpRouter<T> {
    pub async fn listen(&self, database: KrbDatabase<T>, cache: KrbCache) -> HostResult<()> {
        let listener = TcpListener::bind(&self.addr).await?;

        loop {
            let (stream, addr) = listener.accept().await?;

            tokio::spawn({
                let mut entry = TcpEntry::new(stream, self.receiver.clone());
                let pool = database.clone();
                let cache = cache.clone();
                async move {
                    println!("Connection from {} accepted", addr);
                    let result = entry.handle(pool, cache).await;

                    handle_result_at_router(addr, result)
                }
            });
        }
    }
}
