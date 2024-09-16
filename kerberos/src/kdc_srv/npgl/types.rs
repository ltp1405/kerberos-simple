use std::time::Duration;

use async_trait::async_trait;
use der::{Decode, Sequence};
use kerberos_infra::server::{
    cache::Cacheable,
    database::{Database, ExposeSecret, KrbV5Queryable},
};
use messages::{
    basic_types::{EncryptionKey, OctetString, PrincipalName, Realm},
    Encode, LastReq,
};
use sqlx::PgPool;

use crate::service_traits::{
    LastReqDatabase, LastReqEntry, PrincipalDatabase, PrincipalDatabaseRecord, ReplayCache,
    ReplayCacheEntry,
};

pub struct NpglKdcDbView<'a>(&'a dyn Database<Inner = PgPool>);

impl<'a> NpglKdcDbView<'a> {
    pub fn new(database: &'a dyn Database<Inner = PgPool>) -> Self {
        Self(database)
    }
}

#[async_trait]
impl PrincipalDatabase for NpglKdcDbView<'_> {
    async fn get_principal(
        &self,
        principal_name: &PrincipalName,
        realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord> {
        let realm = realm.as_str();

        let principal_name = principal_name.name_string().first()?.as_str();

        let principal = self
            .0
            .get_principal(principal_name, realm)
            .await
            .ok()?
            .map(|view| {
                let keyvalue = OctetString::new(view.key.expose_secret().clone())
                    .expect("Failed to create OctetString");

                PrincipalDatabaseRecord {
                    max_renewable_life: Duration::from_secs(view.max_renewable_life as u64),
                    max_lifetime: Duration::from_secs(view.max_lifetime as u64),
                    key: EncryptionKey::new(1, keyvalue),
                    p_kvno: Some(view.p_kvno as u32),
                    supported_encryption_types: view.supported_enctypes,
                }
            });

        principal
    }
}

pub struct NpglKdcCacheView<'a>(&'a mut dyn Cacheable<Vec<u8>, Vec<u8>>);

#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
struct LastReqEntryKey {
    realm: Realm,
    name: PrincipalName,
}

impl From<&LastReqEntry> for LastReqEntryKey {
    fn from(entry: &LastReqEntry) -> Self {
        Self {
            realm: entry.realm.clone(),
            name: entry.name.clone(),
        }
    }
}

impl<'a> NpglKdcCacheView<'a> {
    pub fn new(cache: &'a mut dyn Cacheable<Vec<u8>, Vec<u8>>) -> Self {
        Self(cache)
    }
}

#[async_trait]
impl ReplayCache for NpglKdcCacheView<'_> {
    type ReplayCacheError = String;

    async fn store(&self, entry: &ReplayCacheEntry) -> Result<(), Self::ReplayCacheError> {
        let key = entry.to_der().expect("Failed to encode");

        self.0.put(key.clone(), key).await.unwrap();

        Ok(())
    }

    async fn contain(&self, entry: &ReplayCacheEntry) -> Result<bool, Self::ReplayCacheError> {
        let key = entry.to_der().expect("Failed to encode");

        let result = self.0.get(&key).await;

        Ok(result.is_ok())
    }
}

#[async_trait]
impl LastReqDatabase for NpglKdcCacheView<'_> {
    async fn get_last_req(&self, realm: &Realm, principal_name: &PrincipalName) -> Option<LastReq> {
        let key = LastReqEntryKey {
            realm: realm.clone(),
            name: principal_name.clone(),
        }
        .to_der()
        .expect("Failed to encode");

        let value = self.0.get(&key).await.ok()?;

        let last_req = LastReq::from_der(&value).ok()?;

        Some(last_req)
    }

    async fn store_last_req(&self, last_req_entry: LastReqEntry) {
        let key = LastReqEntryKey::from(&last_req_entry)
            .to_der()
            .expect("Failed to encode");

        let value = last_req_entry.last_req.to_der().expect("Failed to encode");

        self.0.put(key, value).await.unwrap();
    }
}
