use kerberos::client::client_env::ClientEnv;
use kerberos::client::client_env_error::ClientEnvError;
use kerberos::cryptographic_hash::CryptographicHash;
use kerberos::cryptography::Cryptography;
use messages::basic_types::{EncryptionKey, KerberosFlags, KerberosString};
use messages::{AsRep, Decode, EncAsRepPart, EncTgsRepPart, TgsRep};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub struct SendApReqHandler {
    pub name: String,
    pub realm: String,
    pub cache_location: PathBuf,
}

impl SendApReqHandler {
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
}

impl ClientEnv for SendApReqHandler {
    fn get_client_name(&self) -> Result<KerberosString, ClientEnvError> {
        // println!("client name: {:?}", self.name);
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
        #[allow(unreachable_code)]
        !unimplemented!()
    }

    fn get_server_realm(&self) -> Result<KerberosString, ClientEnvError> {
        #[allow(unreachable_code)]
        !unimplemented!()
    }

    fn get_kdc_options(&self) -> Result<KerberosFlags, ClientEnvError> {
        #[allow(unreachable_code)]
        !unimplemented!()
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
        #[allow(unreachable_code)]
        !unimplemented!()
    }

    fn set_clock_diff(
        &self,
        _diff: Duration,
        _is_client_earlier: bool,
    ) -> Result<(), ClientEnvError> {
        todo!()
    }

    fn save_as_reply(&self, _data: &AsRep, _data_part: &EncAsRepPart) -> Result<(), ClientEnvError> {
        #[allow(unreachable_code)]
        !unimplemented!()
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
        _data: &TgsRep,
        _data_part: &EncTgsRepPart,
    ) -> Result<(), ClientEnvError> {
        #[allow(unreachable_code)]
        !unimplemented!()
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

    fn save_subkey(&self, _key: EncryptionKey) -> Result<(), ClientEnvError> {
        #[allow(unreachable_code)]
        !unimplemented!()
    }

    fn save_seq_number(&self, _seq_num: u32) -> Result<(), ClientEnvError> {
        #[allow(unreachable_code)]
        !unimplemented!()
    }
}
