use std::io;

pub enum HostError {
    Actionable {
        reply: Vec<u8>,
    },
    Aborted {
        cause: Option<Box<dyn std::error::Error>>,
    },
    Ignorable,
}

impl From<&str> for HostError {
    fn from(err: &str) -> Self {
        HostError::Actionable {
            reply: err.as_bytes().to_vec(),
        }
    }
}

impl From<io::Error> for HostError {
    fn from(err: io::Error) -> Self {
        HostError::Aborted {
            cause: Some(Box::new(err)),
        }
    }
}

impl From<std::net::AddrParseError> for HostError {
    fn from(err: std::net::AddrParseError) -> Self {
        HostError::Aborted {
            cause: Some(Box::new(err)),
        }
    }
}

impl From<Box<dyn std::error::Error>> for HostError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        HostError::Aborted { cause: Some(err) }
    }
}

impl std::fmt::Debug for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostError::Actionable { reply } => {
                write!(
                    f,
                    "Actionable error: {:?}",
                    String::from_utf8(reply.clone()).unwrap()
                )
            }
            HostError::Aborted { cause: err } => {
                write!(f, "Aborted error: {:?}", err)
            }
            HostError::Ignorable => {
                write!(f, "Ignorable error")
            }
        }
    }
}

unsafe impl Send for HostError {}

pub type HostResult<T> = Result<T, HostError>;
