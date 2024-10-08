use crate::client::client_env::ClientEnv;
use crate::client::client_env_error::ClientEnvError;
use crate::cryptographic_hash::CryptographicHash;
use crate::cryptography::Cryptography;
use crate::cryptography_error::CryptographyError;
use crate::service_traits::{
    ApReplayCache, ApReplayEntry, ClientAddressStorage, LastReqDatabase, LastReqEntry,
    PrincipalDatabase, PrincipalDatabaseRecord, ReplayCache, ReplayCacheEntry, UserSessionEntry,
    UserSessionStorage,
};
use async_trait::async_trait;
use messages::basic_types::{
    EncryptionKey, HostAddress, Int32, KerberosFlags, KerberosString, OctetString, PrincipalName,
    Realm,
};
use messages::{ApReq, AsRep, AsReq, Decode, EncAsRepPart, EncTgsRepPart, LastReq, TgsRep};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) struct MockedCrypto;

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

pub(crate) struct MockedPrincipalDb {
    data: Arc<Mutex<Vec<(PrincipalName, Realm, PrincipalDatabaseRecord)>>>,
}

impl MockedPrincipalDb {
    pub fn new() -> MockedPrincipalDb {
        MockedPrincipalDb {
            data: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn add_principal(
        &self,
        principal_name: PrincipalName,
        realm: Realm,
        record: PrincipalDatabaseRecord,
    ) {
        self.data
            .lock()
            .unwrap()
            .push((principal_name, realm, record));
    }
}

#[async_trait]
impl PrincipalDatabase for MockedPrincipalDb {
    async fn get_principal(
        &self,
        principal_name: &PrincipalName,
        realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord> {
        self.data
            .lock()
            .unwrap()
            .iter()
            .find_map(|(name, realm, record)| {
                if name == principal_name && realm == realm {
                    Some(record.clone())
                } else {
                    None
                }
            })
    }
}

pub(crate) struct MockClientEnv {
    pub as_req: RefCell<Option<AsReq>>,
    pub as_rep: RefCell<Option<AsRep>>,
    pub enc_as_rep_part: RefCell<Option<EncAsRepPart>>,
    pub tgs_req: RefCell<Option<AsReq>>,
    pub tgs_rep: RefCell<Option<TgsRep>>,
    pub enc_tgs_rep_part: RefCell<Option<EncTgsRepPart>>,
    pub subkey: RefCell<Option<EncryptionKey>>,
    pub seq_number: RefCell<Option<u32>>,
    pub kdc_options: RefCell<Option<KerberosFlags>>,
}

impl MockClientEnv {
    pub(crate) fn new() -> MockClientEnv {
        MockClientEnv {
            as_req: RefCell::new(None),
            as_rep: RefCell::new(None),
            enc_as_rep_part: RefCell::new(None),
            tgs_req: RefCell::new(None),
            tgs_rep: RefCell::new(None),
            enc_tgs_rep_part: RefCell::new(None),
            subkey: RefCell::new(None),
            seq_number: RefCell::new(None),
            kdc_options: RefCell::new(None),
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

    fn get_kdc_options(&self) -> Result<KerberosFlags, ClientEnvError> {
        Ok(self
            .kdc_options
            .borrow()
            .clone()
            .unwrap_or(KerberosFlags::builder().build().unwrap()))
    }

    fn get_supported_etypes(&self) -> Result<Vec<i32>, ClientEnvError> {
        Ok(vec![1])
    }

    fn get_crypto(&self, _etype: i32) -> Result<Box<dyn Cryptography>, ClientEnvError> {
        Ok(Box::new(MockedCrypto))
    }

    fn get_checksum_hash(
        &self,
        checksum_type: i32,
    ) -> Result<Box<dyn CryptographicHash>, ClientEnvError> {
        if checksum_type == 1 {
            Ok(Box::new(MockedHasher))
        } else {
            Err(ClientEnvError {
                message: "Unsupported checksum type".to_string(),
            })
        }
    }

    fn get_supported_checksums(&self) -> Result<Vec<i32>, ClientEnvError> {
        Ok(vec![1])
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

    fn save_as_reply(&self, data: &AsRep, data_part: &EncAsRepPart) -> Result<(), ClientEnvError> {
        self.enc_as_rep_part.replace(Some(data_part.clone()));
        self.as_rep.replace(Some(data.clone()));
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

    fn save_tgs_reply(
        &self,
        data: &TgsRep,
        data_part: &EncTgsRepPart,
    ) -> Result<(), ClientEnvError> {
        self.enc_tgs_rep_part.replace(Some(data_part.clone()));
        self.tgs_rep.replace(Some(data.clone()));
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
        match self.enc_tgs_rep_part.borrow().as_ref() {
            None => Err(ClientEnvError {
                message: "No TGS reply enc part".to_string(),
            }),
            Some(data) => Ok(data.to_owned()),
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

pub(crate) struct MockedReplayCache {
    entries: Arc<Mutex<Vec<ReplayCacheEntry>>>,
}

impl MockedReplayCache {
    pub(crate) fn new() -> MockedReplayCache {
        MockedReplayCache {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl ReplayCache for MockedReplayCache {
    type ReplayCacheError = ();

    async fn store(&self, entry: &ReplayCacheEntry) -> Result<(), Self::ReplayCacheError> {
        self.entries.lock().unwrap().push(entry.to_owned());
        Ok(())
    }

    async fn contain(&self, entry: &ReplayCacheEntry) -> Result<bool, Self::ReplayCacheError> {
        Ok(self.entries.lock().unwrap().iter().any(|e| e == entry))
    }
}

pub(crate) struct MockedHasher;

impl CryptographicHash for MockedHasher {
    fn get_checksum_type(&self) -> Int32 {
        1
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        data.iter().rev().cloned().collect()
    }
}

pub(crate) struct MockedLastReqDb {
    entries: Arc<Mutex<Vec<LastReqEntry>>>,
}

impl MockedLastReqDb {
    pub(crate) fn new() -> MockedLastReqDb {
        MockedLastReqDb {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl LastReqDatabase for MockedLastReqDb {
    async fn get_last_req(&self, realm: &Realm, principal_name: &PrincipalName) -> Option<LastReq> {
        self.entries.lock().unwrap().iter().find_map(|entry| {
            if entry.realm == *realm && entry.name == *principal_name {
                Some(entry.last_req.clone())
            } else {
                None
            }
        })
    }

    async fn store_last_req(&self, last_req_entry: LastReqEntry) {
        self.entries.lock().unwrap().push(last_req_entry);
    }
}

pub struct MockedApReplayCache {
    entries: Arc<Mutex<Vec<ApReplayEntry>>>,
}

impl MockedApReplayCache {
    pub(crate) fn new() -> MockedApReplayCache {
        MockedApReplayCache {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl ApReplayCache for MockedApReplayCache {
    type ApReplayCacheError = ();

    async fn store(&self, entry: &ApReplayEntry) -> Result<(), Self::ApReplayCacheError> {
        self.entries.lock().unwrap().push(entry.to_owned());
        Ok(())
    }

    async fn contain(&self, entry: &ApReplayEntry) -> Result<bool, Self::ApReplayCacheError> {
        Ok(self.entries.lock().unwrap().iter().any(|e| e == entry))
    }
}

pub(crate) struct MockedClientAddressStorage {
    addresses: Arc<Mutex<Vec<(ApReq, HostAddress)>>>,
}

impl MockedClientAddressStorage {
    pub(crate) fn new() -> MockedClientAddressStorage {
        MockedClientAddressStorage {
            addresses: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn add_address(&self, req: ApReq, address: HostAddress) {
        self.addresses.lock().unwrap().push((req, address));
    }
}

#[async_trait]
impl ClientAddressStorage for MockedClientAddressStorage {
    type Error = ();
    async fn get_sender_of_packet(&self, req: &ApReq) -> Result<HostAddress, Self::Error> {
        Ok(self.addresses
            .lock()
            .unwrap()
            .iter()
            .find_map(|(r, a)| if r == req { Some(a.clone()) } else { None })
            .unwrap())
    }
}

pub struct MockedUserSessionStorage {
    sessions: Arc<Mutex<Vec<UserSessionEntry>>>,
}

impl MockedUserSessionStorage {
    pub fn new() -> MockedUserSessionStorage {
        MockedUserSessionStorage {
            sessions: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl UserSessionStorage for MockedUserSessionStorage {
    type Error = ();

    async fn get_session(
        &self,
        cname: &PrincipalName,
        crealm: &Realm,
    ) -> Result<Option<UserSessionEntry>, Self::Error> {
        Ok(self.sessions.lock().unwrap().iter().find_map(|s| {
            if &s.cname == cname && &s.crealm == crealm {
                Some(s.clone())
            } else {
                None
            }
        }))
    }

    async fn store_session(&self, session: &UserSessionEntry) -> Result<(), Self::Error> {
        self.sessions.lock().unwrap().push(session.clone());
        Ok(())
    }
}
