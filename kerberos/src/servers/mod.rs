use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;
use guard::Guard;

mod guard;
mod tcp_server;
mod udp_server;

#[async_trait]
pub trait Server {
    type Proto: Guard;
    async fn run(&self) -> Result<(), Box<dyn Error>>;
}
