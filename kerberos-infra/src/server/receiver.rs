use async_trait::async_trait;

use super::KrbInfraResult;

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
pub trait AsyncReceiver: Clone + Copy + Send + Sync {
    async fn receive(&self, bytes: &[u8]) -> KrbInfraResult<Vec<u8>>;

    fn error(&self, err: ExchangeError) -> KrbInfraResult<Vec<u8>>;
}
