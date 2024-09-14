use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use der::Sequence;
use kerberos::service_traits::{UserSessionEntry, UserSessionStorage};
use messages::{basic_types::{EncryptionKey, PrincipalName, Realm}, Encode};
use tokio::sync::Mutex;

use super::error::ApplicationSessionStorageError;

#[derive(Clone)]
pub struct ApplicationSessionStorage {
    pub session_storage: Arc<Mutex<HashMap<String, (EncryptionKey, i32)>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct AppServerSessionRequest {
    cname: PrincipalName,
    crealm: Realm,
}

impl ApplicationSessionStorage {
    pub fn new() -> Self {
        Self {
            session_storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl UserSessionStorage for ApplicationSessionStorage {
    type Error = ApplicationSessionStorageError;
    async fn get_session(
        &self,
        cname: &PrincipalName,
        crealm: &Realm,
    ) -> Result<Option<UserSessionEntry>, Self::Error> {
        let session_storage = self.session_storage.lock().await;

        let key = map_der_to_string(&AppServerSessionRequest {
            cname: cname.clone(),
            crealm: crealm.clone(),
        });
        let session = session_storage.get(&key);
        match session {
            Some((key, sequence_number)) => Ok(Some(UserSessionEntry {
                cname: cname.clone(),
                crealm: crealm.clone(),
                sequence_number: *sequence_number,
                session_key: key.clone(),
            })),
            None => Ok(None),
        }
    }
    async fn store_session(&self, session: &UserSessionEntry) -> Result<(), Self::Error> {
        let mut session_storage = self.session_storage.lock().await;
        let key = map_der_to_string(&AppServerSessionRequest {
            cname: session.cname.clone(),
            crealm: session.crealm.clone(),
        });
        session_storage.insert(key, (session.session_key.clone(), session.sequence_number));
        Ok(())
    }
}

fn map_der_to_string<T: Encode>(der: &T) -> String {
    let encoded = der.to_der().expect("Failed to encode");

    let key: String = String::from_utf8(encoded).unwrap();

    key
}