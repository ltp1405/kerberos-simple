mod sendable;
mod errors;
mod entry;

#[cfg(feature = "tcp")]
mod tcp;

#[cfg(feature = "udp")]
mod udp;

pub use errors::{KrbInfraCltErr, KrbInfraCltResult};
pub use sendable::Sendable;

#[cfg(feature = "tcp")]
pub use tcp::TcpClient;

#[cfg(feature = "udp")]
pub use udp::UdpClient;
