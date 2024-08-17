use std::io;

pub enum KrbInfraError {
    Actionable {
        reply: Vec<u8>,
    },
    Aborted {
        cause: Option<Box<dyn std::error::Error>>,
    },
    Ignorable,
}

impl From<&str> for KrbInfraError {
    fn from(err: &str) -> Self {
        KrbInfraError::Actionable {
            reply: err.as_bytes().to_vec(),
        }
    }
}

impl From<io::Error> for KrbInfraError {
    fn from(err: io::Error) -> Self {
        KrbInfraError::Aborted {
            cause: Some(Box::new(err)),
        }
    }
}

impl From<std::net::AddrParseError> for KrbInfraError {
    fn from(err: std::net::AddrParseError) -> Self {
        KrbInfraError::Aborted {
            cause: Some(Box::new(err)),
        }
    }
}

impl From<Box<dyn std::error::Error>> for KrbInfraError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        KrbInfraError::Aborted { cause: Some(err) }
    }
}

impl std::fmt::Debug for KrbInfraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KrbInfraError::Actionable { reply } => {
                write!(
                    f,
                    "Actionable error: {:?}",
                    String::from_utf8(reply.clone()).unwrap()
                )
            }
            KrbInfraError::Aborted { cause: err } => {
                write!(f, "Aborted error: {:?}", err)
            }
            KrbInfraError::Ignorable => {
                write!(f, "Ignorable error")
            }
        }
    }
}

unsafe impl Send for KrbInfraError {}

pub type KrbInfraResult<T> = Result<T, KrbInfraError>;
