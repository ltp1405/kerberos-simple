use crate::config::{AppConfig, TransportType};
use config::ConfigError;
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

pub struct Client {
    pub name: String,
    pub realm: String,
    pub renewable: bool,
    pub server_name: Option<String>,
    pub server_realm: Option<String>,
    pub server_address: Option<String>,
    pub sender: Option<Box<dyn Sendable>>,
    pub key: Option<String>,
    pub cache_location: PathBuf,
    pub transport_type: TransportType,
}

impl Client {
    pub fn new(
        cfg: AppConfig,
        renewable: bool,
        server_realm: Option<String>,
        server_name: Option<String>,
        server_address: Option<String>,
        password: Option<String>,
        cache_location: PathBuf,
    ) -> Result<Client, ConfigError> {
        let sender: Option<Box<dyn Sendable>> = if let Some(ref server_address) = server_address {
            let client: Box<dyn Sendable> = match &cfg.transport_type.unwrap_or(TransportType::Tcp)
            {
                TransportType::Tcp => {
                    Box::new(TcpClient::new(SocketAddr::V4(server_address.parse().or(
                        Err(ConfigError::Message("Failed to parse address".to_string())),
                    )?)))
                }
                TransportType::Udp => Box::new(UdpClient::new(
                    SocketAddr::V4(cfg.address.parse().or(Err(ConfigError::Message(
                        "Failed to parse address".to_string(),
                    )))?),
                    SocketAddr::V4(server_address.parse().or(Err(ConfigError::Message(
                        "Failed to parse address".to_string(),
                    )))?),
                )),
            };
            Some(client)
        } else {
            None
        };
        Ok(Client {
            name: cfg.name,
            realm: cfg.realm,
            key: cfg.key.or(password),
            cache_location: cfg.cache_location.unwrap_or(cache_location),
            renewable,
            server_name,
            server_realm,
            server_address,
            sender,
            transport_type: cfg.transport_type.unwrap_or(TransportType::Tcp),
        })
    }

    fn open_file_and_write(
        &self,
        folder_name: Option<&str>,
        name: &str,
        data: &[u8],
    ) -> std::io::Result<()> {
        let mut loc = self.cache_location.clone();
        match folder_name {
            None => {}
            Some(folder) => {
                loc.push(folder);
                fs::create_dir_all(loc.clone())?;
            }
        }
        loc.push(name);
        fs::write(loc, data)?;
        Ok(())
    }

    fn open_file_and_read(
        &self,
        folder_name: Option<&str>,
        name: &str,
    ) -> std::io::Result<Vec<u8>> {
        let mut loc = self.cache_location.clone();
        match folder_name {
            None => {}
            Some(folder) => {
                loc.push(folder);
                fs::create_dir_all(loc.clone())?;
            }
        }
        loc.push(name);
        fs::read(loc)
    }

    pub fn list_tickets(&self) -> Vec<EncAsRepPart> {
        let mut loc = self.cache_location.clone();
        loc.push("enc_as_rep_part");

        let entries: Vec<_> = fs::read_dir(loc).unwrap().filter_map(Result::ok).collect();
        let mut tickets = vec![];
        entries.iter().for_each(|entry| {
            let path = entry.path();
            if let Some(file_name) = path.file_name() {
                let b = self
                    .open_file_and_read(Some("enc_as_rep_part"), file_name.to_str().unwrap())
                    .unwrap();
                let part = EncAsRepPart::from_der(&b).unwrap();
                // println!("{:?}", part);
                tickets.push(part);
            }
        });
        tickets
    }
}

impl ClientEnv for Client {
    fn get_client_name(&self) -> Result<KerberosString, ClientEnvError> {
        self.name.clone().try_into().map_err(|_| ClientEnvError {
            message: "Failed to get client name".to_string(),
        })
    }

    fn get_client_realm(&self) -> Result<KerberosString, ClientEnvError> {
        self.realm.clone().try_into().map_err(|_| ClientEnvError {
            message: "Failed to get client realm".to_string(),
        })
    }

    fn get_server_name(&self) -> Result<KerberosString, ClientEnvError> {
        KerberosString::new(self.server_name.as_ref().unwrap().as_bytes()).or(Err(ClientEnvError {
            message: "Failed to get server name".to_string(),
        }))
    }

    fn get_server_realm(&self) -> Result<KerberosString, ClientEnvError> {
        KerberosString::new(self.server_realm.as_ref().unwrap().as_bytes()).or(Err(ClientEnvError {
            message: "Failed to get server realm".to_string(),
        }))
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
        let mut loc = self.cache_location.clone();
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
        self.open_file_and_write(
            Some("as_rep_enc_part"),
            data_part.authtime().timestamp().to_string().as_str(),
            &data_part.to_der().unwrap(),
        )
        .map_err(|_| ClientEnvError {
            message: "".to_string(),
        })?;
        self.open_file_and_write(
            Some("as_rep"),
            data_part.authtime().timestamp().to_string().as_str(),
            &data.to_der().unwrap(),
        )
        .map_err(|_| ClientEnvError {
            message: "".to_string(),
        })
    }

    fn get_as_reply(&self) -> Result<AsRep, ClientEnvError> {
        let mut loc = self.cache_location.clone();
        loc.push("as_rep");

        let mut entries: Vec<_> = fs::read_dir(loc).unwrap().filter_map(Result::ok).collect();
        entries.sort_by_key(|dir| dir.path());
        match entries.first() {
            Some(first_entry) => {
                let path = first_entry.path();
                match path.file_name() {
                    Some(file_name) => self
                        .open_file_and_read(Some("as_rep"), file_name.to_str().unwrap())
                        .map(|b| AsRep::from_der(&b).unwrap())
                        .map_err(|_| ClientEnvError {
                            message: "Failed to read file".to_string(),
                        }),
                    None => Err(ClientEnvError {
                        message: "Failed to read file".to_string(),
                    }),
                }
            }
            None => Err(ClientEnvError {
                message: "Failed to read file".to_string(),
            }),
        }
    }

    fn get_as_reply_enc_part(&self) -> Result<EncAsRepPart, ClientEnvError> {
        let mut loc = self.cache_location.clone();
        loc.push("as_rep_enc_part");

        let mut entries: Vec<_> = fs::read_dir(loc).unwrap().filter_map(Result::ok).collect();
        entries.sort_by_key(|dir| dir.path());
        match entries.first() {
            Some(first_entry) => {
                let path = first_entry.path();
                match path.file_name() {
                    Some(file_name) => self
                        .open_file_and_read(Some("as_rep_enc_part"), file_name.to_str().unwrap())
                        .map(|b| EncAsRepPart::from_der(&b).unwrap())
                        .map_err(|_| ClientEnvError {
                            message: "Failed to read file".to_string(),
                        }),
                    None => Err(ClientEnvError {
                        message: "Failed to read file".to_string(),
                    }),
                }
            }
            None => Err(ClientEnvError {
                message: "Failed to read file".to_string(),
            }),
        }
    }

    fn save_tgs_reply(
        &self,
        data: &TgsRep,
        data_part: &EncTgsRepPart,
    ) -> Result<(), ClientEnvError> {
        self.open_file_and_write(
            Some("tgs_rep_enc_part"),
            data_part.authtime().timestamp().to_string().as_str(),
            &data_part.to_der().unwrap(),
        )
        .map_err(|_| ClientEnvError {
            message: "".to_string(),
        })?;
        self.open_file_and_write(
            Some("tgs_rep"),
            data_part.authtime().timestamp().to_string().as_str(),
            &data.to_der().unwrap(),
        )
        .map_err(|_| ClientEnvError {
            message: "".to_string(),
        })
    }

    fn get_tgs_reply(&self) -> Result<TgsRep, ClientEnvError> {
        let mut loc = self.cache_location.clone();
        loc.push("tgs_rep");

        let mut entries: Vec<_> = fs::read_dir(loc).unwrap().filter_map(Result::ok).collect();
        entries.sort_by_key(|dir| dir.path());
        match entries.first() {
            Some(first_entry) => {
                let path = first_entry.path();
                match path.file_name() {
                    Some(file_name) => self
                        .open_file_and_read(Some("tgs_rep"), file_name.to_str().unwrap())
                        .map(|b| TgsRep::from_der(&b).unwrap())
                        .map_err(|_| ClientEnvError {
                            message: "Failed to read file".to_string(),
                        }),
                    None => Err(ClientEnvError {
                        message: "Failed to read file".to_string(),
                    }),
                }
            }
            None => Err(ClientEnvError {
                message: "Failed to read file".to_string(),
            }),
        }
    }

    fn get_tgs_reply_enc_part(&self) -> Result<EncTgsRepPart, ClientEnvError> {
        let mut loc = self.cache_location.clone();
        loc.push("tgs_rep_enc_part");

        let mut entries: Vec<_> = fs::read_dir(loc).unwrap().filter_map(Result::ok).collect();
        entries.sort_by_key(|dir| dir.path());
        match entries.first() {
            Some(first_entry) => {
                let path = first_entry.path();
                match path.file_name() {
                    Some(file_name) => self
                        .open_file_and_read(Some("tgs_rep_enc_part"), file_name.to_str().unwrap())
                        .map(|b| EncTgsRepPart::from_der(&b).unwrap())
                        .map_err(|_| ClientEnvError {
                            message: "Failed to read file".to_string(),
                        }),
                    None => Err(ClientEnvError {
                        message: "Failed to read file".to_string(),
                    }),
                }
            }
            None => Err(ClientEnvError {
                message: "Failed to read file".to_string(),
            }),
        }
    }

    fn save_subkey(&self, key: EncryptionKey) -> Result<(), ClientEnvError> {
        self.open_file_and_write(None, "subkey", &key.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })
    }

    fn save_seq_number(&self, seq_num: u32) -> Result<(), ClientEnvError> {
        self.open_file_and_write(None, "seq_number", &seq_num.to_der().unwrap())
            .map_err(|_| ClientEnvError {
                message: "Failed to read file".to_string(),
            })
    }
}
