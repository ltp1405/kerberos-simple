use std::time::Duration;
use messages::basic_types::{EncryptionKey, Int32, PrincipalName, Realm, UInt32};

pub(crate) struct PrincipalDatabaseRecord {
    pub key: EncryptionKey,
    pub p_kvno: Option<UInt32>,
    pub max_renewable_life: Duration,
    pub supported_encryption_types: Vec<Int32>,
}

pub trait PrincipalDatabase {
    fn get_principal(
        &self,
        principal_name: &PrincipalName,
        realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord>;
}
