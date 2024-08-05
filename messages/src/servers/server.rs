use std::net::SocketAddr;
use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Server {
    addr: SocketAddr,
}

impl Server {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn run(&self) -> tokio::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        println!("Server running on {}", self.addr);

        loop {
            let (mut socket, _) = listener.accept().await?;
            tokio::spawn(async move {
                let mut buffer = vec![0; 1024];
                match socket.read(&mut buffer).await {
                    Ok(n) if n == 0 => return,
                    Ok(n) => {
                        println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));
                        if let Err(e) = socket.write_all(b"Hello from server!").await {
                            eprintln!("Failed to write to socket; err = {:?}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to read from socket; err = {:?}", e);
                    }
                }
            });
        }
    }

    pub async fn respond(&self, mut socket: TcpStream, message: &[u8]) -> tokio::io::Result<()> {
        socket.write_all(message).await?;
        println!("Server sent: {}", String::from_utf8_lossy(message));
        Ok(())
    }
}