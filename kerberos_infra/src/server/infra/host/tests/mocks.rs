use crate::server::{
    infra::{
        cache::{cacheable::Cacheable, error::CacheResult},
        database::{Database, DatabaseResult, KrbV5Queryable, Migration},
        host::{AsyncReceiver, ExchangeError, HostResult},
        KrbDbSchema,
    },
    KrbCache, KrbDatabase,
};
use async_trait::async_trait;
use sqlx::PgPool;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MockASReceiver;

impl MockASReceiver {
    pub const MOCK_MESSAGE: &'static str = "Hello, I am the authentication service";
    pub const MOCK_INVALID_LENGTH_PREFIX_RESPONSE: &'static str = "Invalid length prefix";
    pub const MOCK_UDP_PACKET_OVERSIZE_RESPONSE: &'static str = "UDP packet oversize";
}

#[async_trait]
impl AsyncReceiver for MockASReceiver {
    type Db = PgPool;

    async fn receive(
        &self,
        _bytes: &[u8],
        _pool: KrbDatabase<PgPool>,
        _cache: KrbCache,
    ) -> HostResult<Vec<u8>> {
        let messages = Self::MOCK_MESSAGE.as_bytes();
        Ok(messages.to_vec())
    }

    fn error(&self, err: ExchangeError) -> HostResult<Vec<u8>> {
        let message = match err {
            ExchangeError::LengthPrefix { value: _ } => Self::MOCK_INVALID_LENGTH_PREFIX_RESPONSE,
            ExchangeError::UdpPacketOversize {
                maximum_length: _,
                length: _,
            } => Self::MOCK_UDP_PACKET_OVERSIZE_RESPONSE,
        };

        Ok(message.as_bytes().to_vec())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MockTgsReceiver;

impl MockTgsReceiver {
    pub const MOCK_MESSAGE: &'static str = "Hello, I am the ticket-granting service";
    pub const MOCK_INVALID_LENGTH_PREFIX_RESPONSE: &'static str = "Invalid length prefix";
    pub const MOCK_UDP_PACKET_OVERSIZE_RESPONSE: &'static str = "UDP packet oversize";
}

#[async_trait]
impl AsyncReceiver for MockTgsReceiver {
    type Db = PgPool;

    async fn receive(
        &self,
        _bytes: &[u8],
        _pool: KrbDatabase<PgPool>,
        _cache: KrbCache,
    ) -> HostResult<Vec<u8>> {
        let messages = Self::MOCK_MESSAGE.as_bytes();
        Ok(messages.to_vec())
    }

    fn error(&self, err: ExchangeError) -> HostResult<Vec<u8>> {
        let message = match err {
            ExchangeError::LengthPrefix { value: _ } => Self::MOCK_INVALID_LENGTH_PREFIX_RESPONSE,
            ExchangeError::UdpPacketOversize {
                maximum_length: _,
                length: _,
            } => Self::MOCK_UDP_PACKET_OVERSIZE_RESPONSE,
        };

        Ok(message.as_bytes().to_vec())
    }
}

pub struct MockPool;

#[async_trait]
impl Migration for MockPool {
    async fn migrate_then_seed(&mut self) -> DatabaseResult {
        Ok(())
    }
}

#[async_trait]
impl KrbV5Queryable for MockPool {}

#[async_trait]
impl Database for MockPool {
    type Inner = PgPool;

    fn inner(&self) -> &Self::Inner {
        unimplemented!()
    }

    fn inner_mut(&mut self) -> &mut Self::Inner {
        unimplemented!()
    }

    fn get_schema(&self) -> &KrbDbSchema {
        unimplemented!()
    }
}

pub struct MockCache;

#[async_trait]
impl Cacheable<Vec<u8>, Vec<u8>> for MockCache {
    async fn get(&self, key: &Vec<u8>) -> CacheResult<Vec<u8>> {
        Ok(key.clone())
    }

    async fn put(&self, _key: Vec<u8>, _value: Vec<u8>) -> CacheResult<()> {
        Ok(())
    }
}
