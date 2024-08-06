use std::net::SocketAddr;
use std::time::{SystemTime, SystemTimeError};

pub struct Server {
    addr: SocketAddr,
}

impl Server {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn run(&self) -> tokio::io::Result<()> {
        todo!();
    }

    pub async fn return_client_timestamp(&self) -> Result<SystemTime, SystemTimeError> {
        todo!();
    }

    pub async fn decrypt_ticket(&self, ticket: Vec<u8>) -> tokio::io::Result<()> {
        todo!();
    }

    pub async fn validate_authenticator(&self, authenticator: Vec<u8>) -> bool {
        todo!();
    }
}