use std::net::SocketAddr;

pub trait Transporter {
    fn send(&self, bytes: Vec<u8>, destination: SocketAddr) -> tokio::io::Result<()>;
    fn receive(&self) -> tokio::io::Result<Vec<u8>>;
}