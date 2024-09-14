use std::{collections::HashMap, sync::Arc};

use tokio::sync::Mutex;

pub struct ApplicationAuthenticationCache {
    cache: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl ApplicationAuthenticationCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn store(&self, username: String, sequence_number: Vec<u8>) {
        let mut cache = self.cache.lock().await;
        cache.insert(username, sequence_number);
    }

    pub async fn contains(&self, username: &str, sequence_number: Vec<u8>) -> bool {
        let cache = self.cache.lock().await;
        match cache.get(username) {
            Some(seq) => seq == &sequence_number,
            None => false,
        }
    }
}