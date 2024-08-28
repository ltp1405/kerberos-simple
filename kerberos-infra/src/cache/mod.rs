use std::{borrow::BorrowMut, cell::RefCell, collections::HashMap, hash::Hash, num::{NonZero, NonZeroUsize}, rc::Rc, sync::{Arc, RwLock}, time::{Duration, Instant}};

use async_trait::async_trait;
use cacheable::Cacheable;
use error::CacheResult;
use lru::LruCache;

pub mod error;
pub mod cacheable;
pub struct Cache<K, V> 
{
    storage: Arc<RwLock<LruCache<K, (V, Instant)>>>,
    ttl: Duration
}

impl<K, V> Cache<K, V> 
    where K: Eq + Hash + Send + Sync, V: Clone + Send + Sync
{
    pub fn new(capacity: NonZeroUsize, ttl: Duration) -> Self {
        let storage = Arc::new(RwLock::new(LruCache::new(capacity)));
        Cache {
            storage,
            ttl,
        }
    }
}

#[async_trait]
impl <K, V> Cacheable<K, V> for Cache<K, V> 
    where K: Eq + Hash + Send + Sync + Clone, V: Clone + Send + Sync
{
    async fn get(&mut self, key: &K) -> CacheResult<V> {
        let mut storage = self.storage.write().unwrap();
        match storage.get(key) {
            Some((value, instant)) => {
                if instant.elapsed() < self.ttl {
                    Ok(value.clone())
                } else {
                    storage.pop(key);
                    Err(error::CacheErr::ValueExpired)
                }
            },
            None => Err(error::CacheErr::MissingKey)
        }
    }

    async fn put(&mut self, key: K, value: V) -> CacheResult<()> {
        let mut storage = self.storage.write().unwrap();
        if storage.len() == storage.cap().into() {
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
    use std::time::Duration;

    #[tokio::test]
    async fn cache_should_be_able_to_store_and_retrieve_values() {
        let mut cache = Cache::new(NonZeroUsize::new(2).unwrap(), Duration::from_secs(1));
        cache.put("key1", "value1").await.unwrap();
        cache.put("key2", "value2").await.unwrap();
        assert_eq!(cache.get(&"key1").await.unwrap(), "value1");
        assert_eq!(cache.get(&"key2").await.unwrap(), "value2");
    }

    #[tokio::test]
    async fn cache_should_expire_values() {
        let mut cache = Cache::new(NonZeroUsize::new(2).unwrap(), Duration::from_secs(1));
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
        let mut cache = Cache::new(NonZeroUsize::new(2).unwrap(), Duration::from_secs(1));
        cache.put("key1", "value1").await.unwrap();
        cache.put("key2", "value2").await.unwrap();
        cache.put("key3", "value3").await.unwrap();
        assert_eq!(cache.get(&"key1").await, Err(error::CacheErr::MissingKey));
        assert_eq!(cache.get(&"key2").await.unwrap(), "value2");
        assert_eq!(cache.get(&"key3").await.unwrap(), "value3");
    }
}