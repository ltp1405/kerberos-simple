use crate::Cli;
use config::{Config, ConfigError};
use kerberos::client::client_env::ClientEnv;
use kerberos::client::client_env_error::ClientEnvError;
use kerberos::cryptography::Cryptography;
use messages::basic_types::{EncryptionKey, KerberosFlags};
use messages::flags::KdcOptionsFlag;
use messages::{AsRep, Decode, Encode, TgsRep};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

struct Client {
    renewable: bool,
    server_name: String,
    server_realm: String,
    cfg: AppConfig,
}

impl Client {
    fn open_file_and_write(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        let mut loc = self
            .cfg
            .cache_location
            .clone()
            .unwrap_or(PathBuf::from("./"));
        loc.push(name);
        fs::write(loc, data)?;
        Ok(())
    }

    fn open_file_and_read(&self, name: &str) -> std::io::Result<Vec<u8>> {
        let mut loc = self
            .cfg
            .cache_location
            .clone()
            .unwrap_or(PathBuf::from("./"));
        loc.push(name);
        fs::read(loc)
    }
}

impl ClientEnv for Client {
    fn get_client_name(&self) -> Result<messages::basic_types::KerberosString, ClientEnvError> {
        self.cfg
            .name
            .clone()
            .try_into()
            .map_err(|_| ClientEnvError {
                message: "Failed to get client name".to_string(),
            })
    }

    fn get_client_realm(&self) -> Result<messages::basic_types::KerberosString, ClientEnvError> {
        self.cfg
            .realm
            .clone()
            .try_into()
            .map_err(|_| ClientEnvError {
                message: "Failed to get client realm".to_string(),
            })
    }

    fn get_server_name(&self) -> Result<messages::basic_types::KerberosString, ClientEnvError> {
        todo!()
    }

    fn get_server_realm(&self) -> Result<messages::basic_types::KerberosString, ClientEnvError> {
        todo!()
    }

    fn get_kdc_options(&self) -> Result<messages::basic_types::KerberosFlags, ClientEnvError> {
        let mut flag = KerberosFlags::builder();
        if self.renewable {
            flag.set(KdcOptionsFlag::RENEWABLE as usize);
        }
        Ok(flag.build().unwrap())
    }

    fn get_supported_etypes(&self) -> Result<Vec<i32>, ClientEnvError> {
        Ok(vec![1])
    }

    fn get_crypto(&self, etype: i32) -> Result<Box<dyn Cryptography>, ClientEnvError> {
        todo!()
    }

    fn get_client_key(
        &self,
        key_type: i32,
    ) -> Result<messages::basic_types::EncryptionKey, ClientEnvError> {
        let mut loc = self
            .cfg
            .cache_location
            .clone()
            .unwrap_or(PathBuf::from("./"));
        loc.push("key");
        let mut f = std::fs::File::open(loc).map_err(|_| ClientEnvError {
            message: "Failed to fetch key".to_string(),
        })?;
        let mut buf = vec![];
        f.read_to_end(&mut buf).expect("TODO: panic message");
        Ok(EncryptionKey::from_der(&buf).unwrap())
    }

    fn set_clock_diff(
        &self,
        diff: Duration,
        is_client_earlier: bool,
    ) -> Result<(), ClientEnvError> {
        todo!()
    }

    fn save_as_reply(&self, data: &messages::AsRep) -> Result<(), ClientEnvError> {
        self.open_file_and_write("as_rep", &data.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "".to_string(),
            })
    }

    fn get_as_reply(&self) -> Result<AsRep, ClientEnvError> {
        self.open_file_and_read("as_rep")
            .map(|b| AsRep::from_der(&b).unwrap())
            .map_err(|_| ClientEnvError {
                message: "".to_string(),
            })
    }

    fn save_tgs_reply(&self, data: &messages::TgsRep) -> Result<(), ClientEnvError> {
        self.open_file_and_write("tgs_rep", &data.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "".to_string(),
            })
    }

    fn get_tgs_reply(&self) -> Result<messages::TgsRep, ClientEnvError> {
        self.open_file_and_read("tgs_rep")
            .map(|b| TgsRep::from_der(&b).unwrap())
            .map_err(|_| ClientEnvError {
                message: "".to_string(),
            })
    }

    fn save_subkey(&self, key: EncryptionKey) -> Result<(), ClientEnvError> {
        self.open_file_and_write("subkey", &key.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "".to_string(),
            })
    }

    fn save_seq_number(&self, seq_num: u32) -> Result<(), ClientEnvError> {
        self.open_file_and_write("seq_number", &seq_num.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "".to_string(),
            })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    name: String,
    realm: String,
    address: String,
    key: String,
    cache_location: Option<PathBuf>,
}

impl AppConfig {
    pub fn init() -> Result<AppConfig, ConfigError> {
        let cfg = Config::builder()
            .add_source(config::File::with_name("./cfg"))
            .build()?;

        cfg.try_deserialize()
    }
}
