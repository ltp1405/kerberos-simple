use async_trait::async_trait;
use router::TcpRouter;
use std::net::SocketAddr;
use tokio::signal;

use super::{receiver::AsyncReceiver, runnable::Runnable};

pub struct TcpServer<A: AsyncReceiver, T: AsyncReceiver> {
    as_entry: (SocketAddr, A),
    tgt_entry: (SocketAddr, T),
    shutdown_rx: Option<tokio::sync::watch::Receiver<()>>,
}

impl<A: AsyncReceiver, T: AsyncReceiver> TcpServer<A, T> {
    pub(crate) fn new(as_entry: (SocketAddr, A), tgt_entry: (SocketAddr, T)) -> Self {
        Self {
            as_entry,
            tgt_entry,
            shutdown_rx: None,
        }
    }

    fn splits(&self) -> (TcpRouter<A>, TcpRouter<T>) {
        (
            TcpRouter::from(self.as_entry),
            TcpRouter::from(self.tgt_entry),
        )
    }

    #[cfg(test)]
    fn controllable(
        as_entry: (SocketAddr, A),
        tgt_entry: (SocketAddr, T),
    ) -> (Self, tokio::sync::watch::Sender<()>) {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
        (
            Self {
                as_entry,
                tgt_entry,
                shutdown_rx: Some(shutdown_rx),
            },
            shutdown_tx,
        )
    }

    #[cfg(test)]
    pub fn local(as_receiver: A, tgt_receiver: T) -> (Self, tokio::sync::watch::Sender<()>) {
        let as_addr = "127.0.0.1:8080".parse().unwrap();
        let tgt_addr = "127.0.0.1:8081".parse().unwrap();

        Self::controllable((as_addr, as_receiver), (tgt_addr, tgt_receiver))
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
    async fn run(&mut self) {
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
            _ = self.shutdown_rx.as_mut().unwrap().changed(), if self.shutdown_rx.is_some() => {
                eprintln!("Shutdown signal received, shutting down.");
            },
        };
    }
}

mod entry;
mod router;
