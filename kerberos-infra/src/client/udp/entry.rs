use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::client::{entry::Entry, KrbInfraCltResult};

pub struct UdpEntry<'a>(&'a mut UdpSocket);

impl<'a> From<&'a mut UdpSocket> for UdpEntry<'a> {
    fn from(stream: &'a mut UdpSocket) -> Self {
        Self(stream)
    }
}

#[async_trait]
impl<'a> Entry for UdpEntry<'a> {
    async fn handle(&mut self, bytes: &[u8]) -> KrbInfraCltResult<Vec<u8>> {
        // For UDP, we don't need to read the length prefix
        // or send it to the server
        self.0.send(bytes).await?;

        let mut buffer = vec![0; 1024];
        let len = self.0.recv(&mut buffer).await?;
        buffer.truncate(len);

        Ok(buffer)
    }
}
