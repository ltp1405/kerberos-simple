use config::{Config, ConfigError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    pub transport_type: TransportType,
}

impl AppConfig {
    pub fn init() -> Result<AppConfig, ConfigError> {
        // let cfg = Config::builder()
        //     .add_source(config::File::with_name("./cfg"))
        //     .build()?;
        //
        // cfg.try_deserialize()
        Ok(AppConfig {
            name: "client".to_string(),
            realm: "realm".to_string(),
            address: "127.0.0.1:88".to_string(),
            key: "key".to_string(),
            cache_location: None,
            transport_type: TransportType::Tcp,
        })
    }
}
