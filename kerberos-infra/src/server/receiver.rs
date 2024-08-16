use async_trait::async_trait;

use super::KrbInfraError;

/// A trait for registering authentication service and
/// ticket-granting service.
pub trait Registerable {
    fn register_as(self, component: impl AsyncReceiver) -> Self;

    fn register_tgs(self, component: impl AsyncReceiver) -> Self;
}

/// A trait for receiving bytes asynchronously from the client
/// through either TcpStream or UdpSocket.
///
/// This trait is used by the `Registerable` trait to register
/// the authentication service and ticket-granting service.
///
/// The `AsyncReceiver` trait is implemented by the guard of server
/// which is responsible for handling the incoming bytes from the client.
///
/// # Example
/// ```no_run
/// struct AuthServiceReceiver;
///
/// #[async_trait]
/// impl AsyncReceiver for AuthServiceReceiver {
///    async fn receive(&self, bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error> {
///       // bytes is the data received from the client
///       // process the data and return the result
///       Ok(vec![])
///   }
/// }
#[async_trait]
pub trait AsyncReceiver: Clone + Copy + Send + Sync {
    type Error: Into<KrbInfraError>;

    async fn receive(&self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
