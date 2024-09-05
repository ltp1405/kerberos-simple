use crate::client::client_env_error::ClientEnvError;
use crate::cryptography_error::CryptographyError;
use messages::KdcReqBodyBuilderError;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum ClientError {
    ClientEnvError(ClientEnvError),
    CryptographyError(CryptographyError),
    PrepareRequestError(KdcReqBodyBuilderError),
    InvalidAsReq(String),
    ReponseDoesNotMatch(String),
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
            ClientError::InvalidAsReq(e) => write!(f, "Invalid AS-REQ: {}", e),
            ClientError::ReponseDoesNotMatch(e) => write!(f, "Response does not match: {}", e),
            ClientError::EncodeError => write!(f, "Encode error"),
            ClientError::DecodeError => write!(f, "Decode error"),
            ClientError::GenericError(e) => write!(f, "Generic error: {}", e),
            _ => write!(f, "Unknown error"),
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
        ClientError::PrepareRequestError(e)
    }
}
