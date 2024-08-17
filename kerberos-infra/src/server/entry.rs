use super::errors::KrbInfraSvrResult;
use async_trait::async_trait;

#[async_trait]
pub trait Entry {
    async fn handle(&mut self) -> KrbInfraSvrResult<()>;
}
