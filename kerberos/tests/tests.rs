use kerberos::client::client_env::ClientEnv;
use kerberos::client::client_env_error::ClientEnvError;
use kerberos::cryptography::Cryptography;
use kerberos::cryptography_error::CryptographyError;
use kerberos::service_traits::{PrincipalDatabase, PrincipalDatabaseRecord};
use messages::basic_types::{
    EncryptionKey, KerberosFlags, KerberosString, OctetString, PrincipalName, Realm,
};
use messages::{AsRep, AsReq, Decode, EncAsRepPart, EncTgsRepPart, TgsRep};
use std::cell::RefCell;
use std::time::Duration;

struct MockedCrypto;

impl Cryptography for MockedCrypto {
    fn get_etype(&self) -> i32 {
        1
    }
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let data = data
            .to_vec()
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
        _principal_name: &PrincipalName,
        _realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord> {
        Some(PrincipalDatabaseRecord {
            key: EncryptionKey::new(1, OctetString::new(vec![1; 8]).unwrap()),
            p_kvno: Some(1),
            max_renewable_life: Duration::from_secs(5 * 60),
            supported_encryption_types: vec![1, 2, 3],
            max_lifetime: Duration::from_secs(24 * 60 * 60),
        })
    }
}

struct MockClientEnv {
    pub as_req: RefCell<Option<AsReq>>,
    pub as_rep: RefCell<Option<AsRep>>,
    pub enc_as_rep_part: RefCell<Option<EncAsRepPart>>,
    pub tgs_req: RefCell<Option<AsReq>>,
    pub tgs_rep: RefCell<Option<TgsRep>>,
    pub enc_tgs_rep_part: RefCell<Option<EncTgsRepPart>>,
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

    fn get_supported_etypes(&self) -> Result<Vec<i32>, ClientEnvError> {
        Ok(vec![1])
    }

    fn get_crypto(&self, _etype: i32) -> Result<Box<dyn Cryptography>, ClientEnvError> {
        Ok(Box::new(MockedCrypto))
    }

    fn get_client_key(&self, _key_type: i32) -> Result<EncryptionKey, ClientEnvError> {
        Ok(EncryptionKey::new(1, OctetString::new(vec![1; 8]).unwrap()))
    }

    fn set_clock_diff(
        &self,
        _diff: Duration,
        _is_client_earlier: bool,
    ) -> Result<(), ClientEnvError> {
        Ok(())
    }

    fn save_as_reply(&self, data: &AsRep) -> Result<(), ClientEnvError> {
        let enc_part = data.enc_part().clone();
        let decrypted_enc_part = EncAsRepPart::from_der(
            &self
                .get_crypto(*enc_part.etype())?
                .decrypt(
                    enc_part.cipher().as_ref(),
                    self.get_client_key(1)?.keyvalue().as_ref(),
                )
                .unwrap(),
        )
        .unwrap();
        self.save_as_reply_enc_part(&decrypted_enc_part)?;
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
        let enc_part = data.enc_part().clone();
        let decrypted_enc_part = EncTgsRepPart::from_der(
            &self
                .get_crypto(*enc_part.etype())?
                .decrypt(enc_part.cipher().as_ref(), [0u8; 4].as_slice())
                .unwrap(),
        )
        .unwrap();
        self.save_tgs_reply_enc_part(&decrypted_enc_part)?;
        self.tgs_rep.replace(Some(data.clone()));
        Ok(())
    }

    fn save_tgs_reply_enc_part(&self, data: &EncTgsRepPart) -> Result<(), ClientEnvError> {
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

    fn get_tgs_reply_enc_part(&self) -> Result<EncTgsRepPart, ClientEnvError> {
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
    use crate::{MockClientEnv, MockedCrypto, MockedPrincipalDb};
    use kerberos::authentication_service::{AuthenticationService, AuthenticationServiceBuilder};
    use kerberos::client::as_exchange::{prepare_as_request, receive_as_response};
    use kerberos::client::client_env::ClientEnv;
    use kerberos::service_traits::PrincipalDatabase;
    use kerberos::ticket_granting_service::TicketGrantingService;
    use messages::basic_types::{
        KerberosString, NameTypes, PrincipalName, Realm,
    };

    fn get_auth_service<P>(db: &P, pre_auth: bool) -> AuthenticationService<P>
    where
        P: PrincipalDatabase,
    {
        AuthenticationServiceBuilder::default()
            .principal_db(db)
            .realm(Realm::new("realm".as_bytes()).unwrap())
            .sname(
                PrincipalName::new(
                    NameTypes::NtPrincipal,
                    [KerberosString::new("server").unwrap()],
                )
                .unwrap(),
            )
            .require_pre_authenticate(pre_auth)
            .supported_crypto_systems(vec![Box::new(MockedCrypto)])
            .build()
            .unwrap()
    }

    #[test]
    fn test_as_exchange() {
        let mock_client_env = MockClientEnv::new();
        let as_req =
            prepare_as_request(&mock_client_env, None, None).expect("Failed to prepare AS request");
        let auth_service = get_auth_service(&MockedPrincipalDb, false);
        let as_rep = auth_service.handle_krb_as_req(&as_req);
        assert!(as_rep.is_ok());
        let as_rep = as_rep.unwrap();
        mock_client_env.save_as_reply(&as_rep).unwrap();
        assert!(receive_as_response(&mock_client_env, &as_req, &as_rep).is_ok());
    }
}
