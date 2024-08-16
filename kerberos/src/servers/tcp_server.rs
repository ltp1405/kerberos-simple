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

    fn run(&self)  {
        tokio::spawn(async move {
            let listener = TcpListener::bind(&self.0).await.expect("Failed to bind TCP listener");

            loop {
                let (stream, _) = listener.accept().await.expect("Failed to accept TCP connection");
                tokio::spawn({
                    let mut guard = Self::Proto::new(stream);
                    async move {
                        let _ = guard.handle().await;
                    }
                });
            }
        });
    }
}
