mod sendable;
mod errors;
mod entry;

#[cfg(feature = "client-tcp")]
mod tcp;

#[cfg(feature = "client-udp")]
mod udp;

pub use errors::{KrbInfraCltErr, KrbInfraCltResult};
pub use sendable::Sendable;

#[cfg(feature = "client-tcp")]
pub use tcp::TcpClient;

#[cfg(feature = "client-udp")]
pub use udp::UdpClient;
