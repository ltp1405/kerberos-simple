use messages::basic_types::{KerberosTime, Microseconds, PrincipalName, Realm};
use std::error::Error;

pub trait KeyFinder {
    fn get_key_for_srealm(&self, srealm: &Realm) -> Option<Vec<u8>>;
}

pub struct ReplayCacheEntry {
    pub server_name: PrincipalName,
    pub client_name: PrincipalName,
    pub time: KerberosTime,
    pub microseconds: Microseconds,
}

pub trait ReplayCache {
    type ReplayCacheError: Error;
    fn store(&self, entry: ReplayCacheEntry) -> Result<(), ReplayCacheEntry>;
    fn contain(&self, entry: ReplayCacheEntry) -> Result<bool, ReplayCacheEntry>;
}
