use async_trait::async_trait;

use crate::server::{AsyncReceiver, KrbInfraError};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MockASReceiver;

impl MockASReceiver {
    pub const MOCK_MESSAGE: &'static str = "Hello, I am the authentication service";
}

#[async_trait]
impl AsyncReceiver for MockASReceiver {
    type Error = MockReceiverError;

    async fn receive(&self, _bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let messages = Self::MOCK_MESSAGE.as_bytes();
        Ok(messages.to_vec())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MockTgtReceiver;

impl MockTgtReceiver {
    pub const MOCK_MESSAGE: &'static str = "Hello, I am the ticket-granting service";
}

#[async_trait]
impl AsyncReceiver for MockTgtReceiver {
    type Error = MockReceiverError;

    async fn receive(&self, _bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let messages = Self::MOCK_MESSAGE.as_bytes();
        Ok(messages.to_vec())
    }
}

pub struct MockReceiverError;

impl From<MockReceiverError> for KrbInfraError {
    fn from(_: MockReceiverError) -> Self {
        KrbInfraError::Other
    }
}
