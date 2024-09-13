use async_trait::async_trait;
use kerberos_infra::server::{
    host::{AsyncReceiver, ExchangeError, HostResult},
    types::{KrbCache, KrbDatabase},
};
use sqlx::PgPool;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SimpleASReceiver;

#[async_trait]
impl AsyncReceiver for SimpleASReceiver {
    type Db = PgPool;

    async fn receive(
        &self,
        bytes: &[u8],
        _database: KrbDatabase,
        _cache: KrbCache,
    ) -> HostResult<Vec<u8>> {
        Ok(bytes.to_vec())
    }

    fn error(&self, err: ExchangeError) -> HostResult<Vec<u8>> {
        let message = match err {
            ExchangeError::LengthPrefix { value: _ } => "Invalid length prefix",
            ExchangeError::UdpPacketOversize {
                maximum_length: _,
                length: _,
            } => "UDP packet oversize",
        };

        Ok(message.as_bytes().to_vec())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SimpleTgtReceiver;

#[async_trait]
impl AsyncReceiver for SimpleTgtReceiver {
    type Db = PgPool;

    async fn receive(
        &self,
        bytes: &[u8],
        _database: KrbDatabase,
        _cache: KrbCache,
    ) -> HostResult<Vec<u8>> {
        Ok(bytes.to_vec())
    }

    fn error(&self, err: ExchangeError) -> HostResult<Vec<u8>> {
        let message = match err {
            ExchangeError::LengthPrefix { value: _ } => "Invalid length prefix",
            ExchangeError::UdpPacketOversize {
                maximum_length: _,
                length: _,
            } => "UDP packet oversize",
        };

        Ok(message.as_bytes().to_vec())
    }
}
