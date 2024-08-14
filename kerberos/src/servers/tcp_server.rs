use std::{error::Error, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::TcpListener;

use super::{guard::TcpStreamGuard, Guard, Server};

pub struct TcpServer(SocketAddr);

impl TcpServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

#[async_trait]
impl Server for TcpServer {
    type Proto = TcpStreamGuard;

    async fn run(&self) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(&self.0).await?;

        loop {
            let (stream, _) = listener.accept().await?;
            tokio::spawn({
                let mut guard = Self::Proto::new(stream);
                async move {
                    let _ = guard.handle().await;
                }
            });
        }
    }
}
