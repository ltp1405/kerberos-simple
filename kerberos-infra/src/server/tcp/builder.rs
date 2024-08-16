use crate::server::{errors::KrbInfraResult, receiver::AsyncReceiver};

use super::TcpServer;

pub struct TcpServerBuilder<A: AsyncReceiver, T: AsyncReceiver> {
    url: String,
    as_entry: Option<(u16, A)>,
    tgt_entry: Option<(u16, T)>,
}

impl<A: AsyncReceiver, T: AsyncReceiver> TcpServerBuilder<A, T> {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            as_entry: None,
            tgt_entry: None,
        }
    }

    pub fn as_entry(mut self, port: u16, receiver: A) -> Self {
        self.as_entry = Some((port, receiver));
        self
    }

    pub fn tgt_entry(mut self, port: u16, receiver: T) -> Self {
        self.tgt_entry = Some((port, receiver));
        self
    }

    pub fn build(self) -> KrbInfraResult<TcpServer<A, T>> {
        match (self.as_entry, self.tgt_entry) {
            (None, None) => Err("Both entry points have not been set for the server".into()),
            (None, Some(_)) => Err("AS entry point has not been set for the server".into()),
            (Some(_), None) => Err("TGT entry point has not been set for the server".into()),
            (Some((as_port, as_receiver)), Some((tgt_port, tgt_receiver))) => {
                let as_addr = format!("{}:{}", self.url, as_port).parse()?;
                let tgt_addr = format!("{}:{}", self.url, tgt_port).parse()?;
                let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
                Ok(TcpServer {
                    as_entry: (as_addr, as_receiver),
                    tgt_entry: (tgt_addr, tgt_receiver),
                    shutdown_tx,
                    shutdown_rx,
                })
            }
        }
    }
}
