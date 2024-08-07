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
        let mut buffer = vec![0; 1024];
        let n = stream.read(&mut buffer).await?;
        buffer.truncate(n);
        Ok(buffer)
    }
}

#[cfg(test)] 
mod test {
    use crate::{client::Client, servers::Server};
    #[tokio::test]
    async fn test_client_send_method() {
        let client = Client::new("127.0.0.1:8081".parse().expect("Unable to parse socket address"));
        let server = Server::new("127.0.0.1:8080".parse().expect("Unable to parse socket address"));
        client.send(b"Hello I'm Kerberos".to_vec(), server).await.expect("Unable to send message");
        assert!(true);
    }

    #[tokio::test]
    async fn test_client_receive_method() {
        let client = Client::new("127.0.0.1:8081".parse().expect("Unable to parse socket address"));
        let server = Server::new("127.0.0.1:8080".parse().expect("Unable to parse socket address"));
        server.send(b"Hello I'm Kerberos".to_vec(), client.clone()).await.expect("Unable to send message");
        assert!(client.receive().await.unwrap() == b"Hello I'm Kerberos".to_vec());
    }
}