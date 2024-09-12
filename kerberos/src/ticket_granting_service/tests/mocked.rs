use crate::cryptographic_hash::CryptographicHash;
use crate::cryptography::Cryptography;
use crate::cryptography_error::CryptographyError;
use crate::service_traits::{
    ApReplayCache, ApReplayEntry, ClientAddressStorage, LastReqDatabase, LastReqEntry,
    PrincipalDatabase, PrincipalDatabaseRecord, ReplayCache, ReplayCacheEntry,
};
use async_trait::async_trait;
use messages::basic_types::{
    EncryptionKey, HostAddress, Int32, KerberosFlags, KerberosString, OctetString, PrincipalName,
    Realm,
};
use messages::{ApReq, AsRep, AsReq, EncAsRepPart, EncTgsRepPart, LastReq, TgsRep};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

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
    async fn get_sender_of_packet(&self, req: &ApReq) -> HostAddress {
        self.addresses
            .lock()
            .unwrap()
            .iter()
            .find_map(|(r, a)| if r == req { Some(a.clone()) } else { None })
            .unwrap()
    }
}
