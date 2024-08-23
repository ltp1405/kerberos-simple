use async_trait::async_trait;

#[async_trait]
pub trait Runnable {
    async fn run(&mut self);
}
