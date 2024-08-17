use std::io;

pub enum KrbInfraSvrErr {
    Actionable {
        reply: Vec<u8>,
    },
    Aborted {
        cause: Option<Box<dyn std::error::Error>>,
    },
    Ignorable,
}

impl From<&str> for KrbInfraSvrErr {
    fn from(err: &str) -> Self {
        KrbInfraSvrErr::Actionable {
            reply: err.as_bytes().to_vec(),
        }
    }
}

impl From<io::Error> for KrbInfraSvrErr {
    fn from(err: io::Error) -> Self {
        KrbInfraSvrErr::Aborted {
            cause: Some(Box::new(err)),
        }
    }
}

impl From<std::net::AddrParseError> for KrbInfraSvrErr {
    fn from(err: std::net::AddrParseError) -> Self {
        KrbInfraSvrErr::Aborted {
            cause: Some(Box::new(err)),
        }
    }
}

impl From<Box<dyn std::error::Error>> for KrbInfraSvrErr {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        KrbInfraSvrErr::Aborted { cause: Some(err) }
    }
}

impl std::fmt::Debug for KrbInfraSvrErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KrbInfraSvrErr::Actionable { reply } => {
                write!(
                    f,
                    "Actionable error: {:?}",
                    String::from_utf8(reply.clone()).unwrap()
                )
            }
            KrbInfraSvrErr::Aborted { cause: err } => {
                write!(f, "Aborted error: {:?}", err)
            }
            KrbInfraSvrErr::Ignorable => {
                write!(f, "Ignorable error")
            }
        }
    }
}

unsafe impl Send for KrbInfraSvrErr {}

pub type KrbInfraSvrResult<T> = Result<T, KrbInfraSvrErr>;
