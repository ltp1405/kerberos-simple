use crate::server::infra::{
    cache::{cacheable::Cacheable, error::CacheResult},
    database::{Database, DatabaseResult, Migration, Queryable},
    host::{AsyncReceiver, ExchangeError, HostResult},
    DataBox,
};
use async_trait::async_trait;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MockASReceiver;

impl MockASReceiver {
    pub const MOCK_MESSAGE: &'static str = "Hello, I am the authentication service"; 
    pub const MOCK_INVALID_LENGTH_PREFIX_RESPONSE: &'static str = "Invalid length prefix";
    pub const MOCK_UDP_PACKET_OVERSIZE_RESPONSE: &'static str = "UDP packet oversize";
}

#[async_trait]
impl AsyncReceiver for MockASReceiver {
    async fn receive(
        &self,
        _bytes: &[u8],
        _pool: DataBox<dyn Database>,
        _cache: DataBox<dyn Cacheable<String, String>>,
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
    async fn receive(
        &self,
        _bytes: &[u8],
        _pool: DataBox<dyn Database>,
        _cache: DataBox<dyn Cacheable<String, String>>,
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
    async fn migrate(&self) -> DatabaseResult {
        Ok(())
    }
}

#[async_trait]
impl Queryable for MockPool {}

#[async_trait]
impl Database for MockPool {}

pub struct MockCache;

#[async_trait]
impl Cacheable<String, String> for MockCache {
    async fn get(&mut self, key: &String) -> CacheResult<String> {
        Ok(key.clone())
    }

    async fn put(&mut self, _key: String, _value: String) -> CacheResult<()> {
        Ok(())
    }
}
