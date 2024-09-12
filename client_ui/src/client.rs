use crate::config::{AppConfig, TransportType};
use config::{Config, ConfigError};
use kerberos::client::client_env::ClientEnv;
use kerberos::client::client_env_error::ClientEnvError;
use kerberos::cryptographic_hash::CryptographicHash;
use kerberos::cryptography::Cryptography;
use kerberos_infra::client::{Sendable, TcpClient, UdpClient};
use messages::basic_types::{EncryptionKey, KerberosFlags, KerberosString, OctetString};
use messages::flags::KdcOptionsFlag;
use messages::{AsRep, Decode, EncAsRepPart, EncTgsRepPart, Encode, TgsRep};
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) struct Client {
    renewable: bool,
    server_name: String,
    server_realm: String,
    server_address: String,
    cfg: AppConfig,
    sender: Box<dyn Sendable>,
}

impl Client {
    pub fn new(
        renewable: bool,
        server_name: String,
        server_realm: String,
        server_address: String,
    ) -> Result<Client, ConfigError> {
        let cfg = AppConfig::init()?;
        let sender: Box<dyn Sendable> = match &cfg.tranport_type {
            TransportType::Tcp => {
                Box::new(TcpClient::new(SocketAddr::V4(cfg.address.parse().unwrap())))
            }
            TransportType::Udp => Box::new(UdpClient::new(
                SocketAddr::V4(cfg.address.parse().unwrap()),
                SocketAddr::V4(cfg.address.parse().unwrap()),
            )),
        };
        Ok(Client {
            renewable,
            server_name,
            server_realm,
            server_address,
            cfg,
            sender,
        })
    }

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
    fn get_client_name(&self) -> Result<KerberosString, ClientEnvError> {
        self.cfg
            .name
            .clone()
            .try_into()
            .map_err(|_| ClientEnvError {
                message: "Failed to get client name".to_string(),
            })
    }

    fn get_client_realm(&self) -> Result<KerberosString, ClientEnvError> {
        self.cfg
            .realm
            .clone()
            .try_into()
            .map_err(|_| ClientEnvError {
                message: "Failed to get client realm".to_string(),
            })
    }

    fn get_server_name(&self) -> Result<KerberosString, ClientEnvError> {
        KerberosString::new(self.server_name.as_bytes()).or(Err(ClientEnvError {
            message: "Failed to get server name".to_string(),
        }))
    }

    fn get_server_realm(&self) -> Result<KerberosString, ClientEnvError> {
        KerberosString::new(self.server_realm.as_bytes()).or(Err(ClientEnvError {
            message: "Failed to get server realm".to_string(),
        }))
    }

    fn get_client_address(&self) -> Result<OctetString, ClientEnvError> {
        todo!()
    }

    fn get_kdc_options(&self) -> Result<KerberosFlags, ClientEnvError> {
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

    fn get_checksum_hash(
        &self,
        checksum_type: i32,
    ) -> Result<Box<dyn CryptographicHash>, ClientEnvError> {
        todo!()
    }

    fn get_supported_checksums(&self) -> Result<Vec<i32>, ClientEnvError> {
        todo!()
    }

    fn get_client_key(&self, key_type: i32) -> Result<EncryptionKey, ClientEnvError> {
        let mut loc = self
            .cfg
            .cache_location
            .clone()
            .unwrap_or(PathBuf::from("./"));
        loc.push("key");
        let mut f = fs::File::open(loc).map_err(|_| ClientEnvError {
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

    fn save_as_reply(&self, data: &AsRep, data_part: &EncAsRepPart) -> Result<(), ClientEnvError> {
        self.open_file_and_write("as_rep_enc_part", &data_part.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "".to_string(),
            })?;
        self.open_file_and_write("as_rep", &data.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "".to_string(),
            })
    }

    fn get_as_reply(&self) -> Result<AsRep, ClientEnvError> {
        self.open_file_and_read("as_rep")
            .map(|b| AsRep::from_der(&b).unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })
    }

    fn get_as_reply_enc_part(&self) -> Result<EncAsRepPart, ClientEnvError> {
        self.open_file_and_read("as_rep_enc_part")
            .map(|b| EncAsRepPart::from_der(&b).unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })
    }

    fn save_tgs_reply(
        &self,
        data: &TgsRep,
        data_part: &EncTgsRepPart,
    ) -> Result<(), ClientEnvError> {
        self.open_file_and_write("tgs_rep_enc_part", &data_part.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })?;
        self.open_file_and_write("tgs_rep", &data.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })
    }

    fn get_tgs_reply(&self) -> Result<TgsRep, ClientEnvError> {
        self.open_file_and_read("tgs_rep")
            .map(|b| TgsRep::from_der(&b).unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })
    }

    fn get_tgs_reply_enc_part(&self) -> Result<EncTgsRepPart, ClientEnvError> {
        self.open_file_and_read("tgs_rep_enc_part")
            .map(|b| EncTgsRepPart::from_der(&b).unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })
    }

    fn save_subkey(&self, key: EncryptionKey) -> Result<(), ClientEnvError> {
        self.open_file_and_write("subkey", &key.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })
    }

    fn save_seq_number(&self, seq_num: u32) -> Result<(), ClientEnvError> {
        self.open_file_and_write("seq_number", &seq_num.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })
    }
}
