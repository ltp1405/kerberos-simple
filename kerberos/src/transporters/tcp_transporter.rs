use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::Transporter;

pub struct TcpTransporter {
    addr: SocketAddr,
    stream: Option<TcpStream>,
}

#[async_trait]
impl Transporter for TcpTransporter {
    async fn new(addr: SocketAddr) -> Self {
        return Self { addr, stream: None };
    }
    async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(self.addr).await?;
        println!("Listening on: {}", self.addr);
        loop {
            let (stream, _) = listener.accept().await?;
            if self.stream.is_none() {
                self.stream = Some(stream);
            }
        }
    }
    async fn connect(&mut self, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
        self.stream = Some(
            TcpStream::connect(addr)
                .await
                .expect("Unable to connect to tcp"),
        );
        Ok(())
    }
    async fn write(&mut self, buf: &[u8]) -> Result<(), Box<dyn Error>> {
        if let Some(ref mut stream) = self.stream {
            stream.write_all(buf).await?;
            println!("Wrote to stream");
            Ok(())
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No stream",
            )));
        }
    }
    async fn read(&mut self, buf: &mut [u8]) -> Result<(), Box<dyn Error>> {
        if let Some(ref mut stream) = self.stream {
            println!("{}", buf.len());
            // stream.read_exact(buf).await?;
            // loop {
            //     let n = stream.read(buf).await?;
            //     if n == 0 {
            //         break;
            //     }
            // }
            Ok(())
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No stream",
            )));
        }
    }
}
