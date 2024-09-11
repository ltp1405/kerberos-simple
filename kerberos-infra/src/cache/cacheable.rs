use async_trait::async_trait;

use super::error::CacheResult;

#[async_trait]
pub trait Cacheable<K, V> {

    async fn get(&mut self, key: &K) -> CacheResult<V>;
    async fn put(&mut self, key: K, value: V) -> CacheResult<()>;
}