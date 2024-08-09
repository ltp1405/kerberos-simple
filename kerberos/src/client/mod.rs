use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use crate::servers::Server;

#[derive(Debug, Clone)]
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
    pub async fn send(&self, bytes: Vec<u8>, destination: Server) -> tokio::io::Result<()> {
        let mut stream = TcpStream::connect(destination.addr()).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok(())
    }
    pub async fn receive(&self) -> tokio::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect(self.addr).await?;
        let mut buffer = Vec::new();
        let n = stream.read_to_end(&mut buffer).await?;
        buffer.truncate(n);
        Ok(buffer)
    }
}

#[cfg(test)] 
mod test {
    use std::{net::SocketAddr, str::FromStr};
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

    use crate::{client::Client, servers::Server};
    #[tokio::test]
    async fn test_client_send_method() {
        // Set up mock server
        let mut ms = mockito::Server::new_async().await;

        // Create a mock endpoint
        let mock = ms.mock("POST", "/")
        .with_status(200)
        .with_body("OK")
        .create_async()
        .await;

        // Create a client
        let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let client = Client::new(client_addr);

        // Create a server
        let server_addr: SocketAddr = ms.host_with_port().parse().unwrap();
        let server = Server::new(server_addr);

        // Test send method
        let result = client.send(b"Hello, world!".to_vec(), server).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_client_receive_method() {
        // Set up a real TCP listener to simulate a server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept the connection and send a response
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"Hello, client!").await.unwrap();
        });

        // Create a client
        let client = Client::new(addr);

        // Test receive method
        let result = client.receive().await;
        assert_eq!(result.unwrap(), b"Hello, client!".to_vec());
    }
}