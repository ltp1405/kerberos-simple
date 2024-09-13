use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use kerberos::service_traits::{ApReplayCache, ApReplayEntry};
use messages::Encode;
use tokio::sync::Mutex;

use super::error::AppServerReplayCacheError;

pub struct AppServerReplayCache {
    pub cache: Arc<Mutex<HashMap<Vec<u8>, bool>>>,
}

impl AppServerReplayCache {
    pub fn new() -> AppServerReplayCache {
        AppServerReplayCache {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ApReplayCache for AppServerReplayCache {
    type ApReplayCacheError = AppServerReplayCacheError;

    async fn store(&self, authenticator: &ApReplayEntry) -> Result<(), Self::ApReplayCacheError> {
        self.cache.try_lock().unwrap().insert(authenticator.to_der().unwrap(), true);
        Ok(())
    }

    async fn contain(&self, authenticator: &ApReplayEntry) -> Result<bool, Self::ApReplayCacheError> {
        let is_contained_key = self.cache.try_lock().unwrap().contains_key(&authenticator.to_der().unwrap());
        Ok(is_contained_key)
    }
}
