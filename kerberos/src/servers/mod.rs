use std::net::SocketAddr;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

use crate::client::Client;
#[derive(Debug, Clone)]
pub struct Server {
    addr: SocketAddr,
}

impl Server {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub fn addr(&self) -> SocketAddr {
        return self.addr;
    }
    
    pub async fn run(&self) -> tokio::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        loop {
            let (mut socket, _) = listener.accept().await?;
            tokio::spawn(async move {
                let mut buffer = vec![0; 1024];
                match socket.read(&mut buffer).await {
                    Ok(n) if n == 0 => return, // Connection closed
                    Ok(n) => {
                        buffer.truncate(n);
                        println!("Received: {:?}", String::from_utf8_lossy(&buffer));
                    }
                    Err(e) => {
                        eprintln!("Failed to read from socket; err = {:?}", e);
                    }
                }
            });
        }
    }
    
    pub async fn send(&self, bytes: Vec<u8>, destination: Client) -> tokio::io::Result<()> {
        let mut stream = TcpStream::connect(destination.addr()).await?;
        println!("Sending: {:?}", String::from_utf8_lossy(&bytes));
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
    async fn test_server_send_method() {
        let client = Client::new("127.0.0.1:8081".parse().expect("Unable to parse socket address"));
        let server = Server::new("127.0.0.1:8080".parse().expect("Unable to parse socket address"));
        server.send(b"Hello I'm Kerberos".to_vec(), client).await.expect("Unable to send message");
        assert!(true);
    }

    #[tokio::test]
    async fn test_server_receive_method() {
        let client = Client::new("127.0.0.1:8081".parse().expect("Unable to parse socket address"));
        let server = Server::new("127.0.0.1:8080".parse().expect("Unable to parse socket address"));
        client.send(b"Hello I'm Kerberos".to_vec(), server.clone()).await.expect("Unable to send message");
        assert!(server.receive().await.unwrap() == b"Hello I'm Kerberos".to_vec());
    }
}