use async_trait::async_trait;

use super::error::CacheResult;

#[async_trait]
pub trait Cacheable<K = String, V = String>: Send + Sync {
    async fn get(&self, key: &K) -> CacheResult<V>;

    async fn put(&self, key: K, value: V) -> CacheResult<()>;
}
