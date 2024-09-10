pub struct HostBuilder {
    url: String,
    as_port: u16,
    tgs_port: u16,
    as_receiver: Option<DataBox<dyn AsyncReceiver>>,
    tgs_receiver: Option<DataBox<dyn AsyncReceiver>>,
}

type EntryPoint = (SocketAddr, DataBox<dyn AsyncReceiver>);

impl HostBuilder {
    pub fn new(settings: ServerSettings) -> Self {
        Self {
            url: settings.host,
            as_port: settings.as_port,
            tgs_port: settings.tgs_port,
            as_receiver: None,
            tgs_receiver: None,
        }
    }

    pub fn as_receiver(mut self, receiver: DataBox<dyn AsyncReceiver>) -> Self {
        self.as_receiver = Some(receiver);
        self
    }

    pub fn tgs_receiver(mut self, receiver: DataBox<dyn AsyncReceiver>) -> Self {
        self.tgs_receiver = Some(receiver);
        self
    }

    fn validate(self) -> KrbInfraSvrResult<(EntryPoint, EntryPoint)> {
        match (self.as_receiver, self.tgs_receiver) {
            (None, None) => Err("Both entry points have not been set for the server".into()),
            (None, Some(_)) => Err("AS entry point has not been set for the server".into()),
            (Some(_), None) => Err("TGT entry point has not been set for the server".into()),
            (Some(as_receiver), Some(tgs_receiver)) => {
                let as_entry = (
                    format!("{}:{}", self.url, self.as_port).parse()?,
                    as_receiver,
                );
                let tgt_entry = (
                    format!("{}:{}", self.url, self.tgs_port).parse()?,
                    tgs_receiver,
                );
                Ok((as_entry, tgt_entry))
            }
        }
    }
}

#[cfg(test)]
impl HostBuilder {
    pub fn local() -> Self {
        use crate::server::config::Protocol;

        Self::new(ServerSettings {
            host: "127.0.0.1".into(),
            as_port: 88,
            tgs_port: 89,
            protocol: Protocol::Tcp,
        })
    }
}

use std::net::SocketAddr;

use crate::server::{config::ServerSettings, infra::DataBox};

#[cfg(feature = "server-tcp")]
use super::TcpHost;
use super::{receiver::AsyncReceiver, KrbInfraSvrResult};

#[cfg(feature = "server-tcp")]
impl HostBuilder {
    pub fn build_tcp(self) -> KrbInfraSvrResult<TcpHost> {
        let (as_addr, tgt_addr) = self.validate()?;
        Ok(TcpHost::new(as_addr, tgt_addr))
    }
}

#[cfg(feature = "server-udp")]
use super::UdpHost;

#[cfg(feature = "server-udp")]
impl HostBuilder {
    pub fn build_udp(self) -> KrbInfraSvrResult<UdpHost> {
        let (as_addr, tgt_addr) = self.validate()?;
        Ok(UdpHost::new(as_addr, tgt_addr))
    }
}
