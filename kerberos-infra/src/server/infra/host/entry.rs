use crate::server::infra::{KrbCache, KrbDatabase};

use super::error::KrbInfraSvrResult;
use async_trait::async_trait;

#[async_trait]
pub trait Entry {
    async fn handle(&mut self, database: KrbDatabase, cache: KrbCache)
        -> KrbInfraSvrResult<()>;
}
