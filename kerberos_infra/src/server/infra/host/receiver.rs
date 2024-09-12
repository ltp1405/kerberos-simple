use async_trait::async_trait;

use crate::server::infra::{KrbCache, KrbDatabase};

use super::HostResult;

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
    type Db;

    async fn receive(
        &self,
        bytes: &[u8],
        database: KrbDatabase<Self::Db>,
        cache: KrbCache,
    ) -> HostResult<Vec<u8>>;

    fn error(&self, err: ExchangeError) -> HostResult<Vec<u8>>;

    // fn boxed(self) -> Box<dyn AsyncReceiver>
    // where
    //     Self: Sized + 'static,
    // {
    //     Box::new(self)
    // }
}


