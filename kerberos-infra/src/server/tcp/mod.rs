use async_trait::async_trait;
use router::Router;
use std::net::SocketAddr;
use tokio::signal;

use super::{errors::KrbInfraResult, receiver::AsyncReceiver, runnable::Runnable};

pub struct TcpServer<A: AsyncReceiver, T: AsyncReceiver> {
    as_entry: (SocketAddr, A),
    tgt_entry: (SocketAddr, T),
    shutdown_tx: tokio::sync::watch::Sender<()>,
    shutdown_rx: tokio::sync::watch::Receiver<()>,
}

impl<A: AsyncReceiver, T: AsyncReceiver> TcpServer<A, T> {
    pub fn builder(url: &str) -> builder::TcpServerBuilder<A, T> {
        builder::TcpServerBuilder::new(url)
    }

    fn splits(&self) -> (Router<A>, Router<T>) {
        (Router::from(self.as_entry), Router::from(self.tgt_entry))
    }

    #[cfg(test)]
    pub fn local(as_receiver: A, tgt_receiver: T) -> Self {
        builder::TcpServerBuilder::new("127.0.0.1")
            .as_entry(8080, as_receiver)
            .tgt_entry(8089, tgt_receiver)
            .build()
            .unwrap()
    }

    #[cfg(test)]
    pub fn as_entry(&self) -> (SocketAddr, A) {
        self.as_entry
    }

    #[cfg(test)]
    pub fn tgt_entry(&self) -> (SocketAddr, T) {
        self.tgt_entry
    }
}

#[async_trait]
impl<A: AsyncReceiver + 'static, T: AsyncReceiver + 'static> Runnable for TcpServer<A, T> {
    async fn run(&mut self) -> KrbInfraResult<()> {
        let (as_router, tgt_router) = self.splits();

        tokio::select! {
            result = as_router.listen() => {
                if let Err(e) = result {
                    eprintln!("AS server failed: {:?}", e);
                }
            },
            result = tgt_router.listen() => {
                if let Err(e) = result {
                    eprintln!("TGT server failed: {:?}", e);
                }
            },
            _ = signal::ctrl_c() => {
                eprintln!("Ctrl+C received, shutting down.");
            },
            _ = self.shutdown_rx.changed() => {
                eprintln!("Shutdown signal received, shutting down.");
            }
        };

        Ok(())
    }

    fn stop(&self) -> KrbInfraResult<()> {
        self.shutdown_tx.send(()).map_err(|_| "")?;
        Ok(())
    }
}

pub mod builder;
mod entry;
mod router;
