use async_trait::async_trait;
use der::Encode;
use kerberos::service_traits::ClientAddressStorage;
use messages::{basic_types::HostAddress, ApReq};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppServerClientStorage {
    pub cache: Arc<Mutex<HashMap<Vec<u8>, HostAddress>>>,
}

impl AppServerClientStorage {
    pub fn new() -> AppServerClientStorage {
        AppServerClientStorage {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn store(&self, authenticator: &ApReq, host_address: &HostAddress) {
        self.cache
            .try_lock()
            .unwrap()
            .insert(authenticator.to_der().unwrap(), host_address.clone());
    }
}

#[async_trait]
impl ClientAddressStorage for AppServerClientStorage {
    async fn get_sender_of_packet(&self, req: &ApReq) -> HostAddress {
        let cache = self.cache.lock().await;
        let host_address = cache.get(&req.to_der().unwrap()).unwrap();
        host_address.clone()
    }
}
