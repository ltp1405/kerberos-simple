use async_trait::async_trait;
use der::Encode;
use kerberos::service_traits::ClientAddressStorage;
use kerberos_infra::server::cache::{Cache, CacheErr, CacheSettings, Cacheable};
use messages::{basic_types::HostAddress, ApReq};

use crate::utils::SrvCacheError;

pub struct AppServerClientStorage(Cache<Vec<u8>, HostAddress>);

impl AppServerClientStorage {
    pub fn new() -> AppServerClientStorage {
        AppServerClientStorage(Cache::from(CacheSettings {
            capacity: std::num::NonZero::new(100).unwrap(),
            ttl: 3600,
        }))
    }

    pub async fn store(
        &self,
        authenticator: &ApReq,
        host_address: &HostAddress,
    ) -> Result<(), SrvCacheError> {
        let key = authenticator
            .to_der()
            .map_err(|_| SrvCacheError::Internal)?;

        self.0.put(key, host_address.clone()).await?;

        Ok(())
    }
}

#[async_trait]
impl ClientAddressStorage for AppServerClientStorage {
    type Error = SrvCacheError;

    async fn get_sender_of_packet(&self, req: &ApReq) -> Result<HostAddress, SrvCacheError> {
        let key = req.to_der().map_err(|_| SrvCacheError::Internal)?;

        let host_address = self.0.get(&key).await?;

        Ok(host_address)
    }
}
