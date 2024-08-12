use std::net::SocketAddr;

use crate::servers::Server;
use crate::transport::{self, Transporter};
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
    pub async fn request_and_respond<T: Transporter>(
        &self,
        request: &[u8],
        destination: Server<T>,
    ) -> tokio::io::Result<Vec<u8>> {
        let mut transporter = T::new_transporter(self.addr).await;
        transporter
            .connect(destination.addr())
            .await
            .expect("Unable to connect to server");
        transporter
            .write(request)
            .await
            .expect("Unable to write to server");
        let mut buffer = vec![0; 1024];
        transporter
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
