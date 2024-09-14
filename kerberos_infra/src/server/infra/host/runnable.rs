use std::net::SocketAddr;

use crate::server::infra::{KrbCache, KrbDatabase};
use async_trait::async_trait;

pub trait Address {
    fn get_as_addr(&self) -> SocketAddr;

    fn get_tgs_addr(&self) -> SocketAddr;
}

#[async_trait]
pub trait Runnable: Address + Send + Sync {
    type Db;

    async fn run(&mut self, database: KrbDatabase<Self::Db>, cache: KrbCache);
}
