pub use error::{HostError, HostResult};
pub use receiver::{AsyncReceiver, ExchangeError};
pub use runnable::Runnable;
pub use builder::HostBuilder;

// Feature-based Public API
#[cfg(feature = "server-tcp")]
pub use tcp::TcpHost;
#[cfg(feature = "server-udp")]
pub use udp::UdpHost;

// Internal module
mod builder;
mod entry;
mod error;
mod receiver;
mod runnable;
mod utils;

// Integration tests module
#[cfg(test)]
mod tests;

// Feature-based internal modules
#[cfg(feature = "server-tcp")]
mod tcp;
#[cfg(feature = "server-udp")]
mod udp;
