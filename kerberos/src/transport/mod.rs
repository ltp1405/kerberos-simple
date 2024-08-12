use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;

pub mod tcp_transport;
pub mod udp_transport;

#[async_trait]
pub trait Transport {
    async fn new_transport(addr: SocketAddr) -> Self;
    async fn connect(&mut self, addr: SocketAddr) -> Result<(), Box<dyn Error>>;
    async fn write(&mut self, buf: &[u8]) -> Result<(), Box<dyn Error>>;
    async fn read(&mut self, buf: &mut [u8]) -> Result<(), Box<dyn Error>>;
}
