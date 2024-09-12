use std::path::PathBuf;
use config::{Config, ConfigError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum TransportType {
    Tcp,
    Udp,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    pub name: String,
    pub realm: String,
    pub address: String,
    pub key: String,
    pub cache_location: Option<PathBuf>,
    pub tranport_type: TransportType,
}

impl AppConfig {
    pub fn init() -> Result<AppConfig, ConfigError> {
        let cfg = Config::builder()
            .add_source(config::File::with_name("./cfg"))
            .build()?;

        cfg.try_deserialize()
    }
}