use async_trait::async_trait;
use router::UdpRouter;
use std::net::SocketAddr;
use tokio::signal;

use crate::server::infra::{DataBox, KrbCache, KrbDatabase};

use super::{receiver::AsyncReceiver, runnable::Runnable};

pub struct UdpHost {
    as_entry: (SocketAddr, DataBox<dyn AsyncReceiver>),
    tgt_entry: (SocketAddr, DataBox<dyn AsyncReceiver>),
}

impl UdpHost {
    pub(crate) fn new(
        as_entry: (SocketAddr, DataBox<dyn AsyncReceiver>),
        tgt_entry: (SocketAddr, DataBox<dyn AsyncReceiver>),
    ) -> Self {
        Self {
            as_entry,
            tgt_entry,
        }
    }

    fn splits(&self) -> (UdpRouter, UdpRouter) {
        (
            UdpRouter::new(self.as_entry.clone()),
            UdpRouter::new(self.tgt_entry.clone()),
        )
    }
}

#[async_trait]
impl Runnable for UdpHost {
    async fn run(&mut self, database: KrbDatabase, cache: KrbCache) {
        let (as_router, tgt_router) = self.splits();

        tokio::select! {
            result = as_router.listen(database.clone(), cache.clone()) => {
                if let Err(e) = result {
                    eprintln!("AS server failed: {:?}", e);
                }
            },
            result = tgt_router.listen(database, cache) => {
                if let Err(e) = result {
                    eprintln!("TGT server failed: {:?}", e);
                }
            },
            _ = signal::ctrl_c() => {
                eprintln!("Ctrl+C received, shutting down.");
            }
        };
    }
}

#[cfg(test)]
impl UdpHost {
    pub fn as_entry(&self) -> (SocketAddr, DataBox<dyn AsyncReceiver>) {
        self.as_entry.clone()
    }

    pub fn tgt_entry(&self) -> (SocketAddr, DataBox<dyn AsyncReceiver>) {
        self.tgt_entry.clone()
    }
}

mod entry;
mod router;
