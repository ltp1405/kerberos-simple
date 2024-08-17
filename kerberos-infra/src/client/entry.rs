use async_trait::async_trait;

use super::KrbInfraCltResult;

#[async_trait]
pub trait Entry {
    async fn handle(&mut self, bytes: &[u8]) -> KrbInfraCltResult<Vec<u8>>;
}
