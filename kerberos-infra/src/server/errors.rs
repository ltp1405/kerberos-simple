use std::io;

pub enum KrbInfraError {
    Url { url: String },
    Initialization { error: String },
    Operation { error: Box<dyn std::error::Error> },
    Connection { error: std::io::Error },
    Other,
}

impl From<&str> for KrbInfraError {
    fn from(err: &str) -> Self {
        KrbInfraError::Initialization {
            error: err.to_string(),
        }
    }
}

impl From<io::Error> for KrbInfraError {
    fn from(err: io::Error) -> Self {
        KrbInfraError::Connection { error: err }
    }
}

impl From<std::net::AddrParseError> for KrbInfraError {
    fn from(err: std::net::AddrParseError) -> Self {
        KrbInfraError::Url {
            url: err.to_string(),
        }
    }
}

impl From<Box<dyn std::error::Error>> for KrbInfraError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        KrbInfraError::Operation { error: err }
    }
}

impl std::fmt::Debug for KrbInfraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KrbInfraError::Url { url } => write!(f, "Url error: {}", url),
            KrbInfraError::Initialization { error } => write!(f, "Initialization error: {}", error),
            KrbInfraError::Operation { error } => write!(f, "Operation error: {}", error),
            KrbInfraError::Connection { error } => write!(f, "Connection error: {}", error),
            KrbInfraError::Other => write!(f, "Other error"),
        }
    }
}

unsafe impl Send for KrbInfraError {}

pub type KrbInfraResult<T> = Result<T, KrbInfraError>;
