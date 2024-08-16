use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;
use guard::Guard;
use tcp_client_guard::TcpClientGuard;
use udp_client_guard::UdpClientGuard;
mod guard;
mod tcp_client_guard;
mod udp_client_guard;
pub mod tcp_client;
pub mod udp_client;

#[async_trait]
pub trait Client {
    async fn send_and_receive(
        &mut self,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn Error>>;
    async fn close(&mut self) -> Result<(), Box<dyn Error>>;
}
