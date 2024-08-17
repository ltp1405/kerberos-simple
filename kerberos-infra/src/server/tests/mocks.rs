use async_trait::async_trait;

use crate::server::{AsyncReceiver, ExchangeError, KrbInfraResult};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MockASReceiver;

impl MockASReceiver {
    pub const MOCK_MESSAGE: &'static str = "Hello, I am the authentication service";
    pub const MOCK_INVALID_LENGTH_PREFIX: u32 = 0xdeadbeef;
    pub const MOCK_INVALID_LENGTH_PREFIX_RESPONSE: &'static str = "Invalid length prefix";
    pub const MOCK_UDP_PACKET_OVERSIZE_RESPONSE: &'static str = "UDP packet oversize";
}

#[async_trait]
impl AsyncReceiver for MockASReceiver {
    async fn receive(&self, _bytes: &[u8]) -> KrbInfraResult<Vec<u8>> {
        let messages = Self::MOCK_MESSAGE.as_bytes();
        Ok(messages.to_vec())
    }

    fn error(&self, err: ExchangeError) -> KrbInfraResult<Vec<u8>> {
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
pub struct MockTgtReceiver;

impl MockTgtReceiver {
    pub const MOCK_MESSAGE: &'static str = "Hello, I am the ticket-granting service";
    pub const MOCK_INVALID_LENGTH_PREFIX: u32 = 0xdeadbeef;
    pub const MOCK_INVALID_LENGTH_PREFIX_RESPONSE: &'static str = "Invalid length prefix";
    pub const MOCK_UDP_PACKET_OVERSIZE_RESPONSE: &'static str = "UDP packet oversize";
}

#[async_trait]
impl AsyncReceiver for MockTgtReceiver {
    async fn receive(&self, _bytes: &[u8]) -> KrbInfraResult<Vec<u8>> {
        let messages = Self::MOCK_MESSAGE.as_bytes();
        Ok(messages.to_vec())
    }

    fn error(&self, err: ExchangeError) -> KrbInfraResult<Vec<u8>> {
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
