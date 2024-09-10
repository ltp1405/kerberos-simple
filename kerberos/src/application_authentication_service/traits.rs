use messages::basic_types::{KerberosTime, Microseconds, PrincipalName, Realm};
use std::error::Error;

pub trait KeyFinder {
    fn get_key_for_srealm(&self, srealm: &Realm) -> Option<Vec<u8>>;
}

