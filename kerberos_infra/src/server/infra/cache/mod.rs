use std::{
    hash::Hash,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use cacheable::Cacheable;
use error::CacheResult;
use lru::LruCache;

use crate::server::config::CacheSettings;

pub mod cacheable;
pub mod error;

#[derive(Debug, Clone)]
pub enum CacheResultType {
    None,
    DerBytes(Vec<u8>),
}

pub struct Cache<K, V> {
    storage: Arc<RwLock<LruCache<K, (V, Instant)>>>,
    ttl: Duration,
}

impl<K, V> Cache<K, V>
where
    K: Eq + Hash + Send + Sync + Clone + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn boxed(settings: &CacheSettings) -> Box<dyn Cacheable<K, V>> {
        Box::new(Self::from(settings))
    }
}

impl<K, V> From<&CacheSettings> for Cache<K, V>
where
    K: Eq + Hash + Send + Sync,
    V: Clone + Send + Sync,
{
    fn from(settings: &CacheSettings) -> Self {
        Self {
            storage: Arc::new(RwLock::new(LruCache::new(settings.capacity))),
            ttl: Duration::from_secs(settings.ttl),
        }
    }
}

#[async_trait]
impl<K, V> Cacheable<K, V> for Cache<K, V>
where
    K: Eq + Hash + Send + Sync + Clone,
    V: Clone + Send + Sync,
{
    async fn get(&self, key: &K) -> CacheResult<V> {
        let mut storage = self.storage.write().unwrap();
        match storage.get(key) {
            Some((value, instant)) => {
                if instant.elapsed() < self.ttl {
                    Ok(value.clone())
                } else {
                    storage.pop(key);
                    Err(error::CacheErr::ValueExpired)
                }
            }
            None => Err(error::CacheErr::MissingKey),
        }
    }

    async fn put(&self, key: K, value: V) -> CacheResult<()> {
        let mut storage = self.storage.write().unwrap();
        if storage.len() == storage.cap().get() {
            storage.pop_lru();
            storage.put(key, (value, Instant::now()));
            Ok(())
        } else {
            storage.put(key, (value, Instant::now()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{num::NonZeroUsize, time::Duration};

    fn mock_cache<'a>() -> Cache<&'a str, &'a str> {
        Cache::from(&CacheSettings {
            capacity: NonZeroUsize::new(2).unwrap(),
            ttl: 2,
        })
    }

    #[tokio::test]
    async fn cache_should_be_able_to_store_and_retrieve_values() {
        let cache = mock_cache();
        cache.put("key1", "value1").await.unwrap();
        cache.put("key2", "value2").await.unwrap();
        assert_eq!(cache.get(&"key1").await.unwrap(), "value1");
        assert_eq!(cache.get(&"key2").await.unwrap(), "value2");
    }

    #[tokio::test]
    async fn cache_should_expire_values() {
        let cache = mock_cache();
        cache.put("key1", "value1").await.unwrap();
        cache.put("key2", "value2").await.unwrap();
        assert_eq!(cache.get(&"key1").await.unwrap(), "value1");
        assert_eq!(cache.get(&"key2").await.unwrap(), "value2");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(cache.get(&"key1").await, Err(error::CacheErr::ValueExpired));
        assert_eq!(cache.get(&"key2").await, Err(error::CacheErr::ValueExpired));
    }

    #[tokio::test]
    async fn cache_should_evict_lru_values() {
        let cache = mock_cache();
        cache.put("key1", "value1").await.unwrap();
        cache.put("key2", "value2").await.unwrap();
        cache.put("key3", "value3").await.unwrap();
        assert_eq!(cache.get(&"key1").await, Err(error::CacheErr::MissingKey));
        assert_eq!(cache.get(&"key2").await.unwrap(), "value2");
        assert_eq!(cache.get(&"key3").await.unwrap(), "value3");
    }
}
