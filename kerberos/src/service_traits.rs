use messages::basic_types::{
    EncryptionKey, Int32, KerberosTime, Microseconds, PrincipalName, Realm, UInt32,
};
use std::time::Duration;

pub struct PrincipalDatabaseRecord {
    pub key: EncryptionKey,
    pub p_kvno: Option<UInt32>,
    pub max_renewable_life: Duration,
    pub max_lifetime: Duration,
    pub supported_encryption_types: Vec<Int32>,
}

pub trait PrincipalDatabase {
    fn get_principal(
        &self,
        principal_name: &PrincipalName,
        realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord>;
}

pub struct ReplayCacheEntry {
    pub server_name: PrincipalName,
    pub client_name: PrincipalName,
    pub time: KerberosTime,
    pub microseconds: Microseconds,
}

pub trait ReplayCache {
    type ReplayCacheError;
    fn store(&self, entry: ReplayCacheEntry) -> Result<(), Self::ReplayCacheError>;
    fn contain(&self, entry: ReplayCacheEntry) -> Result<bool, Self::ReplayCacheError>;
}

pub trait TicketHotList {
    type TicketHotListError;
    fn store(&self, ticket: &[u8]) -> Result<(), Self::TicketHotListError>;
    fn contain(&self, ticket: &[u8]) -> Result<bool, Self::TicketHotListError>;
}

#[derive(Debug, Clone)]
pub struct ApReplayEntry {
    pub ctime: KerberosTime,
    pub cusec: Microseconds,
    pub cname: PrincipalName,
    pub crealm: Realm,
}

pub trait ApReplayCache {
    type ApReplayCacheError;
    fn store(&self, entry: &ApReplayEntry) -> Result<(), Self::ApReplayCacheError>;
    fn contain(&self, entry: &ApReplayEntry) -> Result<bool, Self::ApReplayCacheError>;
}
