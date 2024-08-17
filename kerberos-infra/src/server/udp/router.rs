use std::{net::SocketAddr, sync::Arc};

use tokio::{net::UdpSocket, sync::mpsc};

use crate::server::{
    entry::Entry, errors::KrbInfraResult, receiver::AsyncReceiver, utils::handle_result_at_router,
};

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
        let socket = UdpSocket::bind(&self.addr).await?;

        let listener = Arc::new(socket);

        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);

        tokio::spawn({
            let listener = listener.clone();

            let receiver = self.receiver;

            async move {
                while let Some((bytes, addr)) = rx.recv().await {
                    let mut entry = UdpEntry::new(listener.clone(), bytes, addr, receiver);

                    let result = entry.handle().await;

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
