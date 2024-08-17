use async_trait::async_trait;

use crate::server::{AsyncReceiver, ExchangeError, KrbInfraResult};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MockASReceiver;

impl MockASReceiver {
    pub const MOCK_MESSAGE: &'static str = "Hello, I am the authentication service";
    pub const MOCK_INVALID_LENGTH_PREFIX: u32 = 0xdeadbeef;
    pub const MOCK_INVALID_LENGTH_PREFIX_RESPONSE: &'static str = "Invalid length prefix";
}

#[async_trait]
impl AsyncReceiver for MockASReceiver {
    async fn receive(&self, _bytes: &[u8]) -> KrbInfraResult<Vec<u8>> {
        let messages = Self::MOCK_MESSAGE.as_bytes();
        Ok(messages.to_vec())
    }

    fn error(&self, err: ExchangeError) -> KrbInfraResult<Vec<u8>> {
        match err {
            ExchangeError::LengthPrefix { value: _ } => {
                let messages = Self::MOCK_INVALID_LENGTH_PREFIX_RESPONSE.as_bytes();
                Ok(messages.to_vec())
            }
            ExchangeError::UdpPacketOversize { length: _ } => panic!("Unexpected error"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MockTgtReceiver;

impl MockTgtReceiver {
    pub const MOCK_MESSAGE: &'static str = "Hello, I am the ticket-granting service";
    pub const MOCK_INVALID_LENGTH_PREFIX: u32 = 0xdeadbeef;
    pub const MOCK_INVALID_LENGTH_PREFIX_RESPONSE: &'static str = "Invalid length prefix";
}

#[async_trait]
impl AsyncReceiver for MockTgtReceiver {
    async fn receive(&self, _bytes: &[u8]) -> KrbInfraResult<Vec<u8>> {
        let messages = Self::MOCK_MESSAGE.as_bytes();
        Ok(messages.to_vec())
    }

    fn error(&self, err: ExchangeError) -> KrbInfraResult<Vec<u8>> {
        match err {
            ExchangeError::LengthPrefix { value: _ } => {
                let messages = Self::MOCK_INVALID_LENGTH_PREFIX_RESPONSE.as_bytes();
                Ok(messages.to_vec())
            }
            ExchangeError::UdpPacketOversize { length: _ } => panic!("Unexpected error"),
        }
    }
}
