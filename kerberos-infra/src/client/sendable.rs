use async_trait::async_trait;

use super::errors::KrbInfraCltResult;

#[async_trait]
pub trait Sendable {
    async fn send(&mut self, bytes: &[u8]) -> KrbInfraCltResult<Vec<u8>>;
}
