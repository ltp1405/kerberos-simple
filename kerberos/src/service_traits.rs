use messages::basic_types::{
    EncryptionKey, HostAddress, Int32, KerberosTime, Microseconds, PrincipalName, Realm, UInt32,
};
use messages::{ApReq, LastReq};
use std::time::Duration;

pub struct PrincipalDatabaseRecord {
    pub max_renewable_life: Duration,
    pub max_lifetime: Duration,
    pub key: EncryptionKey,
    pub p_kvno: Option<UInt32>,
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

pub trait ClientAddressStorage {
    fn get_sender_of_packet(&self, req: &ApReq) -> HostAddress;
}

pub struct LastReqEntry {
    last_req: LastReq,
    realm: Realm,
    name: PrincipalName,
}

pub trait LastReqDatabase {
    fn get_last_req(&self, realm: &Realm, principal_name: &PrincipalName) -> Option<LastReq>;
    fn store_last_req(&self, last_req_entry: LastReqEntry);
}
