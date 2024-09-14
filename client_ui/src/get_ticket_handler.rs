use crate::config::{AppConfig, TransportType};
use config::ConfigError;
use derive_builder::Builder;
use kerberos::client::as_exchange::{prepare_as_request, receive_as_response};
use kerberos::client::client_env::ClientEnv;
use kerberos::client::client_env_error::ClientEnvError;
use kerberos::client::tgs_exchange::prepare_tgs_request;
use kerberos::cryptographic_hash::CryptographicHash;
use kerberos::cryptography::Cryptography;
use kerberos_infra::client::{Sendable, TcpClient, UdpClient};
use messages::basic_types::{EncryptionKey, KerberosFlags, KerberosString, KerberosTime};
use messages::flags::{KdcOptionsFlag, TicketFlag};
use messages::{AsRep, Decode, EncAsRepPart, EncTgsRepPart, Encode, TgsRep};
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct GetTicketHandler {
    pub name: String,
    pub realm: String,
    pub renewable: bool,
    pub server_name: Option<String>,
    pub server_realm: Option<String>,
    pub as_receiver: Option<SocketAddr>,
    pub tgs_receiver: Option<SocketAddr>,
    pub as_sender: SocketAddr,
    pub tgs_sender: SocketAddr,
    pub key: Option<String>,
    pub cache_location: PathBuf,
    pub transport_type: TransportType,
    pub ticket_lifetime: Option<humantime::Duration>,
    pub ticket_renew_time: Option<humantime::Timestamp>,
}

impl GetTicketHandler {
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

    pub async fn handle(&self) -> Result<(), ConfigError> {
        let as_req = prepare_as_request(
            self,
            self.ticket_lifetime.map(|t| t.into()),
            None,
            self.renewable
                .then(|| self.ticket_renew_time.clone())
                .map(|t| KerberosTime::from_system_time(t.unwrap().into()).unwrap()),
        )
        .unwrap();
        let mut client: Box<dyn Sendable> = match self.transport_type {
            TransportType::Tcp => Box::new(TcpClient::new(self.as_sender)),
            TransportType::Udp => {
                Box::new(UdpClient::new(self.as_receiver.unwrap(), self.as_sender))
            }
        };
        let response = client
            .send(as_req.to_der().unwrap().as_slice())
            .await
            .expect("failed to send");
        let as_rep = AsRep::from_der(response.as_slice()).unwrap();
        println!("{:?}", as_rep);
        let ok = receive_as_response(self, &as_req, &as_rep);
        match ok {
            Ok(_) => {
                println!("Success");
            }
            Err(e) => {
                println!("Failed: {:?}", e);
            }
        }

        let mut client: Box<dyn Sendable> = match self.transport_type {
            TransportType::Tcp => Box::new(TcpClient::new(self.tgs_sender)),
            TransportType::Udp => {
                Box::new(UdpClient::new(self.tgs_receiver.unwrap(), self.tgs_sender))
            }
        };

        let tgs_req = prepare_tgs_request(self).unwrap();
        let response = client
            .send(tgs_req.to_der().unwrap().as_slice())
            .await
            .expect("failed to send");
        let tgs_rep = AsRep::from_der(response.as_slice()).unwrap();
        let ok = receive_as_response(self, &as_req, &tgs_rep);
        match ok {
            Ok(_) => Ok(()),
            Err(e) => {
                println!("Failed: {:?}", e);
                Err(ConfigError::Message("Failed to get ticket".to_string()))
            }
        }
    }
}

impl ClientEnv for GetTicketHandler {
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
        KerberosString::new(self.server_realm.as_ref().unwrap().as_bytes()).or(Err(
            ClientEnvError {
                message: "Failed to get server realm".to_string(),
            },
        ))
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
