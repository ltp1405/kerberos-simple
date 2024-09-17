use std::marker::PhantomData;

use crate::utils::SrvCacheError;
use async_trait::async_trait;
use kerberos::service_traits::{ApReplayCache, ApReplayEntry};
use kerberos_infra::server::cache::{Cache, CacheSettings, Cacheable};
use messages::Encode;

pub struct AppServerReplayCache(Cache<Vec<u8>, PhantomData<bool>>);

impl AppServerReplayCache {
    pub fn new() -> AppServerReplayCache {
        AppServerReplayCache(Cache::from(CacheSettings {
            capacity: std::num::NonZero::new(100).unwrap(),
            ttl: 3600,
        }))
    }
}

#[async_trait]
impl ApReplayCache for AppServerReplayCache {
    type ApReplayCacheError = SrvCacheError;

    async fn store(&self, authenticator: &ApReplayEntry) -> Result<(), Self::ApReplayCacheError> {
        self.0
            .put(authenticator.to_der().unwrap(), PhantomData)
            .await?;

        Ok(())
    }

    async fn contain(
        &self,
        authenticator: &ApReplayEntry,
    ) -> Result<bool, Self::ApReplayCacheError> {
        let key = authenticator
            .to_der()
            .map_err(|_| SrvCacheError::Internal)?;

        self.0.get(&key).await?;

        Ok(true)
    }
}
