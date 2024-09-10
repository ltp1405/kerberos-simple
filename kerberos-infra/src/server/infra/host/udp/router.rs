use std::{net::SocketAddr, sync::Arc};

use tokio::{net::UdpSocket, sync::mpsc};

use crate::server::infra::{
    host::{entry::Entry, utils::handle_result_at_router, AsyncReceiver, HostResult},
    DataBox, KrbCache, KrbDatabase,
};

use super::entry::UdpEntry;

pub struct UdpRouter {
    addr: SocketAddr,
    receiver: DataBox<dyn AsyncReceiver>,
}

impl UdpRouter {
    pub fn new((addr, receiver): (SocketAddr, DataBox<dyn AsyncReceiver>)) -> Self {
        Self { addr, receiver }
    }
}

unsafe impl Send for UdpRouter {}

impl UdpRouter {
    pub async fn listen(
        &self,
        database: KrbDatabase,
        cache: KrbCache,
    ) -> HostResult<()> {
        let socket = UdpSocket::bind(&self.addr).await?;

        let listener = Arc::new(socket);

        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);

        tokio::spawn({
            let listener = listener.clone();
            let receiver = self.receiver.clone();
            async move {
                while let Some((bytes, addr)) = rx.recv().await {
                    let mut entry = UdpEntry::new(listener.clone(), bytes, addr, receiver.clone());

                    let result = entry.handle(database.clone(), cache.clone()).await;

                    handle_result_at_router(addr, result)
                }
            }
        });

        let mut buf = [0; 1024];

        loop {
            let (len, addr) = listener.recv_from(&mut buf).await?;

            tx.send((buf[..len].to_vec(), addr)).await.unwrap();
        }
    }
}
