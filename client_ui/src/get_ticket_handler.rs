use crate::config::TransportType;
use config::ConfigError;
use derive_builder::Builder;
use kerberos::client::as_exchange::{prepare_as_request, receive_as_response};
use kerberos::client::client_env::ClientEnv;
use kerberos::client::client_env_error::ClientEnvError;
use kerberos::client::tgs_exchange::{prepare_tgs_request, receive_tgs_response};
use kerberos::cryptographic_hash::CryptographicHash;
use kerberos::cryptography::Cryptography;
use kerberos_infra::client::{Sendable, TcpClient, UdpClient};
use messages::basic_types::{
    EncryptionKey, KerberosFlags, KerberosString, KerberosTime, OctetString,
};
use messages::flags::KdcOptionsFlag;
use messages::{AsRep, Decode, EncAsRepPart, EncTgsRepPart, Encode, KrbErrorMsg, TgsRep};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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
        // folder_name: Option<&str>,
        name: &str,
        data: &[u8],
    ) -> std::io::Result<()> {
        let mut loc = self.cache_location.clone();
        // match folder_name {
        //     None => {}
        //     Some(folder) => {
        //         loc.push(folder);
        //         fs::create_dir_all(loc.clone())?;
        //     }
        // }
        loc.push(name);
        let mut file = fs::File::create(&loc)?;

        file.write_all(data)?;
        Ok(())
    }

    fn open_file_and_read(
        &self,
        // folder_name: Option<&str>,
        name: &str,
    ) -> std::io::Result<Vec<u8>> {
        let mut loc = self.cache_location.clone();
        // match folder_name {
        //     None => {}
        //     Some(folder) => {
        //         loc.push(folder);
        //         fs::create_dir_all(loc.clone())?;
        //     }
        // }
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
        let as_rep_res = AsRep::from_der(response.as_slice());
        let as_rep = as_rep_res
            .inspect_err(|e| {
                println!("{:#?}", KrbErrorMsg::from_der(response.as_slice()).unwrap());
                // panic!("Failed to get ticket: {:?}", e);
            })
            .unwrap();
        // println!("{:?}", as_rep);
        let ok = receive_as_response(self, &as_req, &as_rep);
        match &ok {
            Ok(_) => {
                // println!("Success");
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
        let tgs_rep = TgsRep::from_der(response.as_slice()).unwrap();
        let ok = receive_tgs_response(&tgs_req, &tgs_rep, self);
        match ok {
            Ok(_) => {
                println!(
                    "Successfully got ticket for {}",
                    tgs_rep
                        .ticket()
                        .sname()
                        .name_string()
                        .first()
                        .unwrap()
                        .as_str()
                );
                Ok(())
            }
            Err(e) => {
                println!("Failed: {:?}", e);
                Err(ConfigError::Message("Failed to get ticket".to_string()))
            }
        }
    }
}

impl ClientEnv for GetTicketHandler {
    fn get_client_name(&self) -> Result<KerberosString, ClientEnvError> {
        // println!("client name: {:?}", self.name);
        self.name.clone().try_into().map_err(|_| ClientEnvError {
            message: "Failed to get client name".to_string(),
        })
    }

    fn get_client_realm(&self) -> Result<KerberosString, ClientEnvError> {
        // println!("client realm: {:?}", self.realm);
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

    fn get_crypto(&self, _etype: i32) -> Result<Box<dyn Cryptography>, ClientEnvError> {
        Ok(Box::new(kerberos::AesGcm::new()))
    }

    fn get_checksum_hash(
        &self,
        _checksum_type: i32,
    ) -> Result<Box<dyn CryptographicHash>, ClientEnvError> {
        Ok(Box::new(kerberos::Sha1::new()))
    }

    fn get_supported_checksums(&self) -> Result<Vec<i32>, ClientEnvError> {
        todo!()
    }

    fn get_client_key(&self, _key_type: i32) -> Result<EncryptionKey, ClientEnvError> {
        let buf = self.key.as_ref().unwrap().as_bytes();
        // println!("client key: {:?}", buf);
        let key = EncryptionKey::new(1, OctetString::new(buf).unwrap());
        Ok(key)
    }

    fn set_clock_diff(
        &self,
        _diff: Duration,
        _is_client_earlier: bool,
    ) -> Result<(), ClientEnvError> {
        todo!()
    }

    fn save_as_reply(&self, data: &AsRep, data_part: &EncAsRepPart) -> Result<(), ClientEnvError> {
        self.open_file_and_write(
            "as_rep_enc_part",
            // data_part.authtime().timestamp().to_string().as_str(),
            &data_part.to_der().unwrap(),
        )
        .map_err(|_| ClientEnvError {
            message: "failed to save as_rep_enc_part".to_string(),
        })?;
        self.open_file_and_write(
            "as_rep",
            // data_part.authtime().timestamp().to_string().as_str(),
            &data.to_der().unwrap(),
        )
        .map_err(|_| ClientEnvError {
            message: "failed to save as_rep".to_string(),
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
        self.open_file_and_write(
            "tgs_rep_enc_part",
            // data_part.authtime().timestamp().to_string().as_str(),
            &data_part.to_der().unwrap(),
        )
        .map_err(|_| ClientEnvError {
            message: "".to_string(),
        })?;
        self.open_file_and_write(
            "tgs_rep",
            // data_part.authtime().timestamp().to_string().as_str(),
            &data.to_der().unwrap(),
        )
        .map_err(|_| ClientEnvError {
            message: "".to_string(),
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
