use std::{collections::HashMap, sync::{Arc, Mutex}};

use async_trait::async_trait;
use kerberos::service_traits::ClientAddressStorage;
use messages::{basic_types::HostAddress, ApReq};

#[derive(Clone)]
pub struct AppServerClientStorage {
    pub cache: Arc<Mutex<HashMap<Vec<u8>, bool>>>,
}

impl AppServerClientStorage {
    pub fn new() -> AppServerClientStorage {
        AppServerClientStorage {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ClientAddressStorage for AppServerClientStorage {
    async fn get_sender_of_packet(&self, req: &ApReq) -> HostAddress {
        todo!()
    }
}
