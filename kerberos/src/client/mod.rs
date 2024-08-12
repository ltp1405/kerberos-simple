use std::net::SocketAddr;

use crate::servers::Server;
use crate::transport::{self, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Client {
    addr: SocketAddr,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
    pub fn addr(&self) -> SocketAddr {
        return self.addr;
    }
    pub async fn request_and_respond<T: Transport>(
        &self,
        request: &[u8],
        destination: Server<T>,
    ) -> tokio::io::Result<Vec<u8>> {
        let mut transport = T::new_transport(self.addr).await;
        transport
            .connect(destination.addr())
            .await
            .expect("Unable to connect to server");
        transport
            .write(request)
            .await
            .expect("Unable to write to server");
        let mut buffer = vec![0; 1024];
        transport
            .read(&mut buffer)
            .await
            .expect("Unable to read from server");
        Ok(buffer)
    }
}

#[cfg(test)]
mod test {
    #[tokio::test]
    async fn test_client_request_and_respond() {}
}
