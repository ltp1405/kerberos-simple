use async_trait::async_trait;

use super::errors::KrbInfraResult;

#[async_trait]
pub trait Runnable {
    async fn run(&mut self) -> KrbInfraResult<()>;
    
    fn stop(&self) -> KrbInfraResult<()>;
}