use std::net::SocketAddr;

use crate::{client::Client, transporters::Transporter};
pub struct Server<T>
where
    T: Transporter,
{
    addr: SocketAddr,
    transporter: Option<T>,
}

impl<T: Transporter> Server<T> {
    pub async fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            transporter: Some(T::new(addr).await),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        return self.addr;
    }
    pub async fn run(&mut self) -> tokio::io::Result<()> {
        if let Some(ref mut transporter) = self.transporter {
            transporter.run().await.expect("Unable to run server");
            Ok(())
        } else {
            self.transporter = Some(T::new(self.addr).await);
            let transporter = self.transporter.as_mut().unwrap();
            transporter.run().await.expect("Unable to run server");
            Ok(())
        }
    }

    pub async fn send(&mut self, bytes: Vec<u8>, destination: Client) -> tokio::io::Result<()> {
        let mut transporter = T::new(self.addr).await;
        transporter
            .connect(destination.addr())
            .await
            .expect("Unable to connect to client");
        transporter
            .write(&bytes)
            .await
            .expect("Unable to write to client");
        Ok(())
    }

    pub async fn receive(&mut self) -> tokio::io::Result<Vec<u8>> {
        if let Some(ref mut transporter) = self.transporter {
            let mut buffer = Vec::new();
            transporter
                .read(&mut buffer)
                .await
                .expect("Unable to read from client");
            Ok(buffer)
        } else {
            Err(tokio::io::Error::new(
                tokio::io::ErrorKind::NotConnected,
                "No stream available",
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    use crate::{client::Client, servers::Server};

    #[tokio::test]
    async fn test_server_send_method() {}

    #[tokio::test]
    async fn test_server_receive_method() {}
}
