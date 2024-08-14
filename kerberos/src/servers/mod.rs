use std::error::Error;

use async_trait::async_trait;
use guard::Guard;

mod guard;
pub mod tcp_server;
pub mod udp_server;

#[async_trait]
pub trait Server {
    type Proto: Guard;
    async fn run(&self) -> Result<(), Box<dyn Error>>;
}
