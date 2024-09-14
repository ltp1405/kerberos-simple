use std::net::SocketAddr;
use config::{Config, ConfigError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use clap::ValueEnum;

#[derive(Debug, Serialize, Deserialize, PartialEq, ValueEnum, Copy, Clone)]
pub enum TransportType {
    Tcp,
    Udp,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    pub name: String,
    pub realm: String,
    pub address: SocketAddr,
    pub key: Option<String>,
    pub cache_location: Option<PathBuf>,
    pub transport_type: Option<TransportType>,
}

impl AppConfig {
    pub fn init(
        config_path: String,
    ) -> Result<AppConfig, ConfigError> {
        let cfg = Config::builder()
            .add_source(config::File::with_name(&config_path))
            .build()?;

        let cfg = cfg.try_deserialize()?;
        Ok(cfg)
    }
}
