use std::net::SocketAddr;

use crate::server::{config::HostSettings, infra::DataBox};

use super::{AsyncReceiver, Runnable};

#[cfg(feature = "server-tcp")]
use super::TcpHost;

#[cfg(feature = "server-udp")]
use super::UdpHost;

pub struct HostBuilder {
    url: String,
    as_port: u16,
    tgs_port: u16,
    as_receiver: Option<DataBox<dyn AsyncReceiver>>,
    tgs_receiver: Option<DataBox<dyn AsyncReceiver>>,
}

pub enum HostBuilderError {
    MissingReceiver,
    InvalidPort,
    InvalidUrl,
}

pub type HostBuilderResult<T = Box<dyn Runnable>> = Result<T, HostBuilderError>;

type EntryPoint = (SocketAddr, DataBox<dyn AsyncReceiver>);

impl std::fmt::Debug for HostBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostBuilderError::MissingReceiver => {
                write!(f, "Missing receiver for the host")
            }
            HostBuilderError::InvalidPort => {
                write!(f, "Invalid port number")
            }
            HostBuilderError::InvalidUrl => {
                write!(f, "Invalid URL")
            }
        }
    }
}

impl std::fmt::Display for HostBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostBuilderError::MissingReceiver => {
                write!(f, "Missing receiver for the host")
            }
            HostBuilderError::InvalidPort => {
                write!(f, "Invalid port number")
            }
            HostBuilderError::InvalidUrl => {
                write!(f, "Invalid URL")
            }
        }
    }
}

impl HostBuilder {
    pub fn new(settings: &HostSettings) -> Self {
        Self {
            url: settings.host.to_owned(),
            as_port: settings.as_port,
            tgs_port: settings.tgs_port,
            as_receiver: None,
            tgs_receiver: None,
        }
    }

    pub fn set_as_receiver(mut self, receiver: DataBox<dyn AsyncReceiver>) -> Self {
        self.as_receiver = Some(receiver);
        self
    }

    pub fn set_tgs_receiver(mut self, receiver: DataBox<dyn AsyncReceiver>) -> Self {
        self.tgs_receiver = Some(receiver);
        self
    }

    fn validate(self) -> HostBuilderResult<(EntryPoint, EntryPoint)> {
        match (self.as_receiver, self.tgs_receiver) {
            (Some(as_receiver), Some(tgs_receiver)) => {
                if self.as_port == 0 || self.tgs_port == 0 || (self.as_port == self.tgs_port) {
                    return Err(HostBuilderError::InvalidPort);
                }
                let as_entry = (
                    format!("{}:{}", self.url, self.as_port)
                        .parse()
                        .map_err(|_| HostBuilderError::InvalidUrl)?,
                    as_receiver,
                );
                let tgt_entry = (
                    format!("{}:{}", self.url, self.tgs_port)
                        .parse()
                        .map_err(|_| HostBuilderError::InvalidUrl)?,
                    tgs_receiver,
                );
                Ok((as_entry, tgt_entry))
            }
            _ => Err(HostBuilderError::MissingReceiver),
        }
    }
}

#[cfg(test)]
impl HostBuilder {
    pub fn local() -> Self {
        use crate::server::config::Protocol;
        
        Self::new(&HostSettings {
            host: "127.0.0.1".into(),
            as_port: 88,
            tgs_port: 89,
            protocol: Protocol::Tcp,
        })
    }
}

#[cfg(feature = "server-tcp")]
impl HostBuilder {
    pub fn boxed_tcp(self) -> HostBuilderResult {
        let (as_addr, tgt_addr) = self.validate()?;
        Ok(Box::new(TcpHost::new(as_addr, tgt_addr)))
    }
}

#[cfg(feature = "server-udp")]
impl HostBuilder {
    pub fn boxed_udp(self) -> HostBuilderResult {
        let (as_addr, tgt_addr) = self.validate()?;
        Ok(Box::new(UdpHost::new(as_addr, tgt_addr)))
    }
}
