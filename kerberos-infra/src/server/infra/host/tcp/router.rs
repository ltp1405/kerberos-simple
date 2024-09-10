use std::net::SocketAddr;

use tokio::net::TcpListener;

use crate::server::infra::{
    host::{entry::Entry, utils::handle_result_at_router, AsyncReceiver, KrbInfraSvrResult},
    DataBox, KrbCache, KrbDatabase,
};

use super::entry::TcpEntry;

pub struct TcpRouter {
    addr: SocketAddr,
    receiver: DataBox<dyn AsyncReceiver>,
}

impl TcpRouter {
    pub fn new(addr: SocketAddr, receiver: DataBox<dyn AsyncReceiver>) -> Self {
        Self { addr, receiver }
    }
}

unsafe impl Send for TcpRouter {}

impl TcpRouter {
    pub async fn listen(
        &self,
        database: KrbDatabase,
        cache: KrbCache,
    ) -> KrbInfraSvrResult<()> {
        let listener = TcpListener::bind(&self.addr).await?;

        loop {
            let (stream, addr) = listener.accept().await?;

            tokio::spawn({
                let mut entry = TcpEntry::new(stream, self.receiver.clone());
                let pool = database.clone();
                let cache = cache.clone();
                async move {
                    let result = entry.handle(pool, cache).await;

                    handle_result_at_router(addr, result)
                }
            });
        }
    }
}
