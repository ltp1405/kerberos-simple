use async_trait::async_trait;

use kerberos_infra::server::{AsyncReceiver, ExchangeError, KrbInfraSvrResult};

use super::mappers::Mapper;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SimpleASReceiver;

#[async_trait]
impl AsyncReceiver for SimpleASReceiver {
    async fn receive(&self, bytes: &[u8]) -> KrbInfraSvrResult<Vec<u8>> {
        let message = String::from_utf8(bytes.to_vec()).unwrap();
        let response = Mapper::prepare().map(&message).to_owned();
        Ok(response.as_bytes().to_vec())
    }

    fn error(&self, err: ExchangeError) -> KrbInfraSvrResult<Vec<u8>> {
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
    async fn receive(&self, bytes: &[u8]) -> KrbInfraSvrResult<Vec<u8>> {
        let message = String::from_utf8(bytes.to_vec()).unwrap();
        let response = Mapper::prepare().map(&message).to_owned();
        Ok(response.as_bytes().to_vec())
    }

    fn error(&self, err: ExchangeError) -> KrbInfraSvrResult<Vec<u8>> {
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
