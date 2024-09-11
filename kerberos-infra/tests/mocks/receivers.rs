use async_trait::async_trait;

use der::{asn1::OctetString, Encode};
use kerberos_infra::server::{AsyncReceiver, ExchangeError, KrbInfraSvrResult};
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SimpleASReceiver;

#[async_trait]
impl AsyncReceiver for SimpleASReceiver {
    async fn receive(&self, bytes: &[u8]) -> KrbInfraSvrResult<Vec<u8>> {
        Ok(bytes.to_vec())
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
        Ok(bytes.to_vec())
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
