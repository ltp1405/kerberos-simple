use async_trait::async_trait;

use crate::server::infra::{KrbCache, KrbDatabase};

use super::KrbInfraSvrResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeError {
    LengthPrefix {
        value: u32,
    },
    UdpPacketOversize {
        maximum_length: usize,
        length: usize,
    },
}

#[async_trait]
pub trait AsyncReceiver: Send + Sync {
    async fn receive(
        &self,
        bytes: &[u8],
        database: KrbDatabase,
        cache: KrbCache,
    ) -> KrbInfraSvrResult<Vec<u8>>;

    fn error(&self, err: ExchangeError) -> KrbInfraSvrResult<Vec<u8>>;
}
