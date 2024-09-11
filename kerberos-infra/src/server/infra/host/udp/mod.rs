use async_trait::async_trait;
use router::UdpRouter;
use std::net::SocketAddr;
use tokio::signal;

use crate::server::infra::{DataBox, KrbCache, KrbDatabase};

use super::{receiver::AsyncReceiver, runnable::{Address, Runnable}};

pub struct UdpHost {
    as_entry: (SocketAddr, DataBox<dyn AsyncReceiver>),
    tgs_entry: (SocketAddr, DataBox<dyn AsyncReceiver>),
}

impl UdpHost {
    pub(crate) fn new(
        as_entry: (SocketAddr, DataBox<dyn AsyncReceiver>),
        tgt_entry: (SocketAddr, DataBox<dyn AsyncReceiver>),
    ) -> Self {
        Self {
            as_entry,
            tgs_entry: tgt_entry,
        }
    }

    fn splits(&self) -> (UdpRouter, UdpRouter) {
        (
            UdpRouter::new(self.as_entry.clone()),
            UdpRouter::new(self.tgs_entry.clone()),
        )
    }
}

impl Address for UdpHost {
    fn get_as_addr(&self) -> SocketAddr {
        self.as_entry.0
    }

    fn get_tgs_addr(&self) -> SocketAddr {
        self.tgs_entry.0
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

mod entry;
mod router;
