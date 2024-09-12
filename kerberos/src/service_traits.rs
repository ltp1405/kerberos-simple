use messages::basic_types::{
    EncryptionKey, HostAddress, Int32, KerberosTime, Microseconds, PrincipalName, Realm, UInt32,
};
use messages::{ApReq, LastReq};
use std::time::Duration;
use async_trait::async_trait;

pub struct PrincipalDatabaseRecord {
    pub max_renewable_life: Duration,
    pub max_lifetime: Duration,
    pub key: EncryptionKey,
    pub p_kvno: Option<UInt32>,
    pub supported_encryption_types: Vec<Int32>,
}

#[async_trait]
pub trait PrincipalDatabase {
    async fn get_principal(
        &self,
        principal_name: &PrincipalName,
        realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCacheEntry {
    pub server_name: PrincipalName,
    pub client_name: PrincipalName,
    pub time: KerberosTime,
    pub microseconds: Microseconds,
}

#[async_trait]
pub trait ReplayCache {
    type ReplayCacheError;
    async fn store(&self, entry: &ReplayCacheEntry) -> Result<(), Self::ReplayCacheError>;
    async fn contain(&self, entry: &ReplayCacheEntry) -> Result<bool, Self::ReplayCacheError>;
}

#[async_trait]
pub trait TicketHotList {
    type TicketHotListError;
    async fn store(&self, ticket: &[u8]) -> Result<(), Self::TicketHotListError>;
    async fn contain(&self, ticket: &[u8]) -> Result<bool, Self::TicketHotListError>;
}

#[derive(Debug, Clone)]
pub struct ApReplayEntry {
    pub ctime: KerberosTime,
    pub cusec: Microseconds,
    pub cname: PrincipalName,
    pub crealm: Realm,
}

#[async_trait]
pub trait ApReplayCache {
    type ApReplayCacheError;
    async fn store(&self, entry: &ApReplayEntry) -> Result<(), Self::ApReplayCacheError>;
    async fn contain(&self, entry: &ApReplayEntry) -> Result<bool, Self::ApReplayCacheError>;
}

#[async_trait]
pub trait ClientAddressStorage {
    async fn get_sender_of_packet(&self, req: &ApReq) -> HostAddress;
}

pub struct LastReqEntry {
    pub last_req: LastReq,
    pub realm: Realm,
    pub name: PrincipalName,
}

#[async_trait]
pub trait LastReqDatabase {
    async fn get_last_req(&self, realm: &Realm, principal_name: &PrincipalName) -> Option<LastReq>;
    async fn store_last_req(&self, last_req_entry: LastReqEntry);
}
