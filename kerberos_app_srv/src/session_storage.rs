use kerberos_infra::server::cache::{Cache, CacheSettings, Cacheable};

use std::num::NonZero;

use crate::utils::SrvCacheError;
use async_trait::async_trait;
use der::Sequence;
use kerberos::service_traits::{UserSessionEntry, UserSessionStorage};
use messages::{
    basic_types::{EncryptionKey, PrincipalName, Realm},
    Encode,
};

pub struct ApplicationSessionStorage(Cache<Vec<u8>, (EncryptionKey, i32)>);

#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct AppServerSessionRequest {
    cname: PrincipalName,
    crealm: Realm,
}

impl ApplicationSessionStorage {
    pub fn new() -> Self {
        Self(Cache::from(CacheSettings {
            capacity: NonZero::new(100).unwrap(),
            ttl: 3600,
        }))
    }
}

#[async_trait]
impl UserSessionStorage for ApplicationSessionStorage {
    type Error = SrvCacheError;

    async fn get_session(
        &self,
        cname: &PrincipalName,
        crealm: &Realm,
    ) -> Result<Option<UserSessionEntry>, Self::Error> {
        let key = AppServerSessionRequest {
            cname: cname.clone(),
            crealm: crealm.clone(),
        }
        .to_der()
        .map_err(|_| SrvCacheError::Internal)?;

        let session = self.0.get(&key).await.ok();

        match session {
            Some((key, sequence_number)) => Ok(Some(UserSessionEntry {
                cname: cname.clone(),
                crealm: crealm.clone(),
                sequence_number,
                session_key: key.clone(),
            })),
            None => Ok(None),
        }
    }

    async fn store_session(&self, session: &UserSessionEntry) -> Result<(), Self::Error> {
        let key = AppServerSessionRequest {
            cname: session.cname.clone(),
            crealm: session.crealm.clone(),
        }
        .to_der()
        .map_err(|_| SrvCacheError::Internal)?;

        self.0
            .put(key, (session.session_key.clone(), session.sequence_number))
            .await?;

        Ok(())
    }
}
