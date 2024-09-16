use async_trait::async_trait;
pub use configs::{AuthenticationServiceConfig, TicketGrantingServiceConfig};

#[async_trait]
pub trait Listen: Sized {
    async fn listen(&mut self) -> Result<(), KdcSrvError>;

    fn load_from_dir(
        as_config: AuthenticationServiceConfig,
        tgs_config: TicketGrantingServiceConfig,
    ) -> Result<Self, KdcSrvError>;

    fn load_from(
        dir: &str,
        as_config: AuthenticationServiceConfig,
        tgs_config: TicketGrantingServiceConfig,
    ) -> Result<Self, KdcSrvError>;
}

#[derive(Debug)]
pub enum KdcSrvError {
    Config(String),
    Internal(String),
    Unexpected(String),
}

pub mod npgl;

pub mod configs;

#[cfg(test)]
mod tests;
