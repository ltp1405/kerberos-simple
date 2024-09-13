use std::time::Duration;

use async_trait::async_trait;
use kerberos_infra::server::{
    cache::Cacheable,
    database::{Database, ExposeSecret, KrbV5Queryable},
};
use messages::{
    basic_types::{EncryptionKey, OctetString, PrincipalName, Realm},
    Decode, Encode,
};
use sqlx::PgPool;

use crate::service_traits::{
    PrincipalDatabase, PrincipalDatabaseRecord, ReplayCache, ReplayCacheEntry,
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

pub struct NpglKdcCacheView<'a>(&'a mut dyn Cacheable<String, String>);

impl<'a> NpglKdcCacheView<'a> {
    pub fn new(cache: &'a mut dyn Cacheable<String, String>) -> Self {
        Self(cache)
    }
}

#[async_trait]
impl ReplayCache for NpglKdcCacheView<'_> {
    type ReplayCacheError = String;

    async fn store(&self, entry: &ReplayCacheEntry) -> Result<(), Self::ReplayCacheError> {
        let encoded = {
            let sname = map_der_to_string(&entry.server_name);
            let cname = map_der_to_string(&entry.client_name);
            let time = map_der_to_string(&entry.time);
            let microseconds = map_der_to_string(&entry.microseconds);
            format!("{}-{}-{}-{}", sname, cname, time, microseconds)
        };

        // self.0.put(encoded, String::new()).await.unwrap();

        Ok(())
    }

    async fn contain(&self, entry: &ReplayCacheEntry) -> Result<bool, Self::ReplayCacheError> {
        todo!()
    }
}

fn map_der_to_string<T: Encode>(der: &T) -> String {
    String::from_der(&der.to_der().expect("Failed to encode")).expect("Failed to encode")
}
