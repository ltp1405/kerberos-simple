use std::net::SocketAddr;

use serde::Deserialize;
use serde_aux::field_attributes::deserialize_number_from_string;

use super::protocol::Protocol;

#[derive(Deserialize, Clone)]
pub struct HostSettings {
    pub protocol: Protocol,
    pub host: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub tgs_port: u16,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub as_port: u16,
}

impl HostSettings {
    pub fn tgs_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.host.parse().expect("Malformed IP Address"),
            self.tgs_port,
        )
    }

    pub fn as_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.host.parse().expect("Malformed IP Address"),
            self.as_port,
        )
    }
}
