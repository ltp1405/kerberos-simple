use crate::server::infra::{KrbCache, KrbDatabase};
use async_trait::async_trait;

#[async_trait]
pub trait Runnable: Send + Sync {
    async fn run(&mut self, database: KrbDatabase, cache: KrbCache);
}
