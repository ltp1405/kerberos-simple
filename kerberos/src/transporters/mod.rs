use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;

pub mod tcp_transporter;
pub mod udp_transporter;

#[async_trait]
pub trait Transporter {
    async fn new(addr: SocketAddr) -> Self;
    async fn run(&mut self) -> Result<(), Box<dyn Error>>;
    async fn connect(&mut self, addr: SocketAddr) -> Result<(), Box<dyn Error>>;
    async fn write(&mut self, buf: &[u8]) -> Result<(), Box<dyn Error>>;
    async fn read(&mut self, buf: &mut [u8]) -> Result<(), Box<dyn Error>>;
}
