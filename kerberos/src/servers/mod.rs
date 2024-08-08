use std::net::SocketAddr;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

use crate::client::Client;
pub struct Server {
    addr: SocketAddr,
    stream: Option<TcpStream>,
}

impl Server {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, stream: None }
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
        let stream = TcpStream::connect(self.addr).await.expect("Unable to connect to socket address");
        if self.stream.is_none() {
            self.stream = Some(stream);
        }
        Ok(())
    }
    pub async fn send(&mut self, bytes: Vec<u8>, destination: Client) -> tokio::io::Result<()> {
        let mut stream = TcpStream::connect(destination.addr()).await.expect("Unable to connect to client");
        println!("Sending: {:?}", String::from_utf8_lossy(&bytes));
        stream.write_all(&bytes).await?;
        Ok(())
        
    }

    pub async fn receive(&mut self) -> tokio::io::Result<Vec<u8>> {
        if let Some(ref mut stream) = self.stream {
            let mut buffer = Vec::new();
            stream.read_to_end(&mut buffer).await?;
            Ok(buffer)
        } else {
            Err(tokio::io::Error::new(tokio::io::ErrorKind::NotConnected, "No stream available"))
        }
    }
}

#[cfg(test)] 
mod test {
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    use crate::{client::Client, servers::Server};

    #[tokio::test]
    async fn test_server_send_method() {
        let ms = mockito::Server::new_async().await;
        // Create a mock client
        let mock_client = Client::new(ms.host_with_port().parse().expect("Unable to parse the socket address"));

        // Create a server instance
        let mut server = Server::new("127.0.0.1:8080".parse().expect("Unable to parse the socket address"));

        println!("server is running");
        // Data to send
        let data = b"Hello, world!".to_vec();

        // Call the send method
        let result = server.send(data.clone(), mock_client).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_server_receive_method() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut server = Server::new(addr);
        // Spawn a task to accept the connection and send a response
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"Hello, client!").await.unwrap();
        });
        server.try_run().await.unwrap();
        assert_eq!(server.receive().await.unwrap(), b"Hello, client!");
    }
}