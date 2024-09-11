use kerberos::client::client_env::ClientEnv;
use kerberos::client::client_env_error::ClientEnvError;
use kerberos::cryptography::Cryptography;
use kerberos::cryptography_error::CryptographyError;
use kerberos::service_traits::PrincipalDatabase;
use messages::basic_types::{
    EncryptionKey, KerberosFlags, KerberosString, OctetString, PrincipalName, Realm,
};
use messages::{AsRep, AsReq, EncAsRepPart, TgsRep};
use std::cell::RefCell;
use std::time::Duration;

struct MockedCrypto;

impl Cryptography for MockedCrypto {
    fn get_etype(&self) -> i32 {
        1
    }
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut data = data.to_vec();
        let data = data
            .iter()
            .zip(key.iter().cycle())
            .map(|(d, k)| *d ^ *k)
            .collect();
        Ok(data)
    }

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        self.encrypt(data, key)
    }

    fn generate_key(&self) -> Result<Vec<u8>, CryptographyError> {
        Ok(vec![0xff; 8])
    }
}

struct MockedPrincipalDb;

impl PrincipalDatabase for MockedPrincipalDb {
    fn get_principal(
        &self,
        principal_name: &PrincipalName,
        realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord> {
        Some(PrincipalDatabaseRecord {
            key: EncryptionKey::new(1, OctetString::new(vec![1; 8]).unwrap()),
            p_kvno: Some(1),
            max_renewable_life: Duration::from_secs(5 * 60),
            supported_encryption_types: vec![1, 2, 3],
        })
    }
}

struct MockClientEnv {
    pub as_req: RefCell<Option<AsReq>>,
    pub as_rep: RefCell<Option<AsRep>>,
    pub enc_as_rep_part: RefCell<Option<EncAsRepPart>>,
    pub tgs_req: RefCell<Option<AsReq>>,
    pub tgs_rep: RefCell<Option<TgsRep>>,
    pub enc_tgs_rep_part: RefCell<Option<EncAsRepPart>>,
    pub subkey: RefCell<Option<EncryptionKey>>,
    pub seq_number: RefCell<Option<u32>>,
}

impl MockClientEnv {
    fn new() -> MockClientEnv {
        MockClientEnv {
            as_req: RefCell::new(None),
            as_rep: RefCell::new(None),
            enc_as_rep_part: RefCell::new(None),
            tgs_req: RefCell::new(None),
            tgs_rep: RefCell::new(None),
            enc_tgs_rep_part: RefCell::new(None),
            subkey: RefCell::new(None),
            seq_number: RefCell::new(None),
        }
    }
}

impl ClientEnv for MockClientEnv {
    fn get_client_name(&self) -> Result<KerberosString, ClientEnvError> {
        Ok(KerberosString::new("client".as_bytes()).unwrap())
    }

    fn get_client_realm(&self) -> Result<KerberosString, ClientEnvError> {
        Ok(KerberosString::new("realm".as_bytes()).unwrap())
    }

    fn get_server_name(&self) -> Result<KerberosString, ClientEnvError> {
        Ok(KerberosString::new("server".as_bytes()).unwrap())
    }

    fn get_server_realm(&self) -> Result<KerberosString, ClientEnvError> {
        Ok(KerberosString::new("realm".as_bytes()).unwrap())
    }

    fn get_client_address(&self) -> Result<OctetString, ClientEnvError> {
        Ok(OctetString::new(vec![0; 4]).unwrap())
    }

    fn get_kdc_options(&self) -> Result<KerberosFlags, ClientEnvError> {
        Ok(KerberosFlags::builder().build().unwrap())
    }

    fn get_current_time(&self) -> Result<Duration, ClientEnvError> {
        Ok(Duration::new(1_000_000, 123))
    }

    fn get_supported_etypes(&self) -> Result<Vec<i32>, ClientEnvError> {
        Ok(vec![1, 2, 3])
    }

    fn get_crypto(&self, _etype: i32) -> Result<Box<dyn Cryptography>, ClientEnvError> {
        Ok(Box::new(MockedCrypto))
    }

    fn get_client_key(&self, _key_type: i32) -> Result<EncryptionKey, ClientEnvError> {
        Ok(EncryptionKey::new(
            1,
            OctetString::new(vec![0, 16]).unwrap(),
        ))
    }

    fn set_clock_diff(
        &self,
        _diff: Duration,
        _is_client_earlier: bool,
    ) -> Result<(), ClientEnvError> {
        Ok(())
    }

    fn save_as_reply(&self, data: &AsRep) -> Result<(), ClientEnvError> {
        self.as_rep.replace(Some(data.clone()));
        Ok(())
    }

    fn save_as_reply_enc_part(&self, data: &EncAsRepPart) -> Result<(), ClientEnvError> {
        self.enc_as_rep_part.replace(Some(data.clone()));
        Ok(())
    }

    fn get_as_reply(&self) -> Result<AsRep, ClientEnvError> {
        match self.as_rep.borrow().clone() {
            None => Err(ClientEnvError {
                message: "No AS reply".to_string(),
            }),
            Some(data) => Ok(data),
        }
    }

    fn get_as_reply_enc_part(&self) -> Result<EncAsRepPart, ClientEnvError> {
        match self.enc_as_rep_part.borrow().clone() {
            None => Err(ClientEnvError {
                message: "No AS reply enc part".to_string(),
            }),
            Some(data) => Ok(data),
        }
    }

    fn save_tgs_reply(&self, data: &TgsRep) -> Result<(), ClientEnvError> {
        self.tgs_rep.replace(Some(data.clone()));
        Ok(())
    }

    fn save_tgs_reply_enc_part(&self, data: &EncAsRepPart) -> Result<(), ClientEnvError> {
        self.enc_tgs_rep_part.replace(Some(data.clone()));
        Ok(())
    }

    fn get_tgs_reply(&self) -> Result<TgsRep, ClientEnvError> {
        match self.tgs_rep.borrow().clone() {
            None => Err(ClientEnvError {
                message: "No TGS reply".to_string(),
            }),
            Some(data) => Ok(data),
        }
    }

    fn get_tgs_reply_enc_part(&self) -> Result<EncAsRepPart, ClientEnvError> {
        match self.enc_tgs_rep_part.borrow().clone() {
            None => Err(ClientEnvError {
                message: "No TGS reply enc part".to_string(),
            }),
            Some(data) => Ok(data),
        }
    }

    fn save_subkey(&self, key: EncryptionKey) -> Result<(), ClientEnvError> {
        self.subkey.replace(Some(key));
        Ok(())
    }

    fn save_seq_number(&self, seq_num: u32) -> Result<(), ClientEnvError> {
        self.seq_number.replace(Some(seq_num));
        Ok(())
    }
}

mod tests {
    use kerberos::client::as_exchange::prepare_as_request;
    use crate::MockClientEnv;

    #[test]
    fn test_as_exchange() {
        let mock_client_env = MockClientEnv::new();
        let as_req = prepare_as_request(
            &mock_client_env,
            None,
            None,
        ).expect("Failed to prepare AS request");
        
        
    }
}
