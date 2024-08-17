use std::net::SocketAddr;

use crate::server::{errors::KrbInfraSvrResult, receiver::AsyncReceiver};

pub struct ServerBuilder<A: AsyncReceiver, T: AsyncReceiver> {
    url: String,
    as_entry: Option<EntryPointConfig<A>>,
    tgt_entry: Option<EntryPointConfig<T>>,
}

type EntryPoint<Receiver> = (SocketAddr, Receiver);
type EntryPointConfig<Receiver> = (u16, Receiver);

impl<A: AsyncReceiver, T: AsyncReceiver> ServerBuilder<A, T> {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            as_entry: None,
            tgt_entry: None,
        }
    }

    pub fn local() -> Self {
        Self::new("127.0.0.1")
    }

    pub fn as_entry(mut self, port: u16, receiver: A) -> Self {
        self.as_entry = Some((port, receiver));
        self
    }

    pub fn tgt_entry(mut self, port: u16, receiver: T) -> Self {
        self.tgt_entry = Some((port, receiver));
        self
    }

    fn validate(self) -> KrbInfraSvrResult<(EntryPoint<A>, EntryPoint<T>)> {
        match (self.as_entry, self.tgt_entry) {
            (None, None) => Err("Both entry points have not been set for the server".into()),
            (None, Some(_)) => Err("AS entry point has not been set for the server".into()),
            (Some(_), None) => Err("TGT entry point has not been set for the server".into()),
            (Some((as_port, as_receiver)), Some((tgt_port, tgt_receiver))) => {
                let as_addr = format!("{}:{}", self.url, as_port).parse()?;
                let tgt_addr = format!("{}:{}", self.url, tgt_port).parse()?;
                Ok(((as_addr, as_receiver), (tgt_addr, tgt_receiver)))
            }
        }
    }
}

#[cfg(feature = "tcp")]
use super::TcpServer;

#[cfg(feature = "tcp")]
impl<A: AsyncReceiver, T: AsyncReceiver> ServerBuilder<A, T> {
    pub fn build_tcp(self) -> KrbInfraSvrResult<TcpServer<A, T>> {
        let (as_addr, tgt_addr) = self.validate()?;
        Ok(TcpServer::new(as_addr, tgt_addr))
    }
}

#[cfg(feature = "udp")]
use super::UdpServer;

#[cfg(feature = "udp")]
impl<A: AsyncReceiver, T: AsyncReceiver> ServerBuilder<A, T> {
    pub fn build_udp(self) -> KrbInfraSvrResult<UdpServer<A, T>> {
        let (as_addr, tgt_addr) = self.validate()?;
        Ok(UdpServer::new(as_addr, tgt_addr))
    }
}
