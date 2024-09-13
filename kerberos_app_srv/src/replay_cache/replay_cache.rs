use std::collections::HashMap;

use async_trait::async_trait;
use kerberos::service_traits::{ApReplayCache, ApReplayEntry};
use messages::Encode;

use super::error::AppServerReplayCacheError;

pub struct AppServerReplayCache {
    pub cache: HashMap<Vec<u8>, bool>,
}

impl AppServerReplayCache {
    pub fn new() -> AppServerReplayCache {
        AppServerReplayCache {
            cache: HashMap::new(),
        }
    }
}

#[async_trait]
impl ApReplayCache for AppServerReplayCache {
    type ApReplayCacheError = AppServerReplayCacheError;

    async fn store(&mut self, authenticator: &ApReplayEntry) -> Result<(), Self::ApReplayCacheError> {
        self.cache.insert(authenticator.to_der().unwrap(), true);
        Ok(())
    }

    async fn contain(&self, authenticator: &ApReplayEntry) -> Result<bool, Self::ApReplayCacheError> {
        let is_contained_key = self.cache.contains_key(&authenticator.to_der().unwrap());
        Ok(is_contained_key)
    }
}
