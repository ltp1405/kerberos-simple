use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    client::Client,
    transport::{self, Transport},
};
pub struct Server<T>
where
    T: Transport,
{
    addr: SocketAddr,
    transport: Option<T>,
}

impl<T: Transport> Server<T> {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            transport: None,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        return self.addr;
    }
    pub async fn run(&mut self) -> tokio::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        loop {
            let (socket, _) = listener.accept().await?;
            if self.stream.is_none() {
                self.stream = Some(socket);
            }
            tokio::spawn(async move {});
        }
    }

    pub async fn try_run(&mut self) -> tokio::io::Result<()> {
        let stream = TcpStream::connect(self.addr)
            .await
            .expect("Unable to connect to socket address");
        if self.stream.is_none() {
            self.stream = Some(stream);
        }
        Ok(())
    }
    pub async fn send(&mut self, bytes: Vec<u8>, destination: Client) -> tokio::io::Result<()> {
        let mut transport = T::new_transport(self.addr).await;
        transport
            .connect(destination.addr())
            .await
            .expect("Unable to connect to client");
        transport
            .write(&bytes)
            .await
            .expect("Unable to write to client");
        Ok(())
    }

    pub async fn receive(&mut self) -> tokio::io::Result<Vec<u8>> {
        if let Some(ref mut transport) = self.transport {
            let mut buffer = Vec::new();
            transport
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
