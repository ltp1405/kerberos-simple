use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;

#[async_trait]
pub trait Guard {
    async fn handle(
        &mut self,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn Error>>;
    async fn close(&mut self) -> Result<(), Box<dyn Error>>;
}


