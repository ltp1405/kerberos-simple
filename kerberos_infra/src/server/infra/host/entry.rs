use crate::server::infra::{KrbCache, KrbDatabase};

use super::error::HostResult;
use async_trait::async_trait;

#[async_trait]
pub trait Entry {
    type Db;

    async fn handle(&mut self, database: KrbDatabase<Self::Db>, cache: KrbCache)
        -> HostResult<()>;
}
