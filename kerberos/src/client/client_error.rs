use crate::client::client_env_error::ClientEnvError;
use crate::cryptography_error::CryptographyError;
use messages::{AuthenticatorBuilderError, KdcReqBodyBuilderError};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum ClientError {
    ClientEnvError(ClientEnvError),
    CryptographyError(CryptographyError),
    PrepareRequestError(String),
    InvalidKdcReq(String),
    ResponseDoesNotMatch(String),
    EncodeError,
    DecodeError,
    GenericError(String),
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::ClientEnvError(e) => write!(f, "ClientEnvError: {}", e),
            ClientError::CryptographyError(e) => write!(f, "ClientError: {}", e),
            ClientError::PrepareRequestError(e) => write!(f, "Prepare request error: {}", e),
            ClientError::InvalidKdcReq(e) => write!(f, "Invalid KDC-REQ: {}", e),
            ClientError::ResponseDoesNotMatch(e) => write!(f, "Response does not match: {}", e),
            ClientError::EncodeError => write!(f, "Encode error"),
            ClientError::DecodeError => write!(f, "Decode error"),
            ClientError::GenericError(e) => write!(f, "Generic error: {}", e),
        }
    }
}

impl Error for ClientError {}

impl From<ClientEnvError> for ClientError {
    fn from(e: ClientEnvError) -> Self {
        ClientError::ClientEnvError(e)
    }
}

impl From<CryptographyError> for ClientError {
    fn from(e: CryptographyError) -> Self {
        ClientError::CryptographyError(e)
    }
}

impl From<KdcReqBodyBuilderError> for ClientError {
    fn from(e: KdcReqBodyBuilderError) -> Self {
        ClientError::PrepareRequestError(e.to_string())
    }
}

impl From<AuthenticatorBuilderError> for ClientError {
    fn from(e: AuthenticatorBuilderError) -> Self {
        ClientError::PrepareRequestError(e.to_string())
    }
}
