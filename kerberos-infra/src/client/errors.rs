pub enum KrbInfraCltErr {
    Io { source: std::io::Error },
}

impl From<std::io::Error> for KrbInfraCltErr {
    fn from(err: std::io::Error) -> Self {
        KrbInfraCltErr::Io { source: err }
    }
}

impl From<std::net::AddrParseError> for KrbInfraCltErr {
    fn from(err: std::net::AddrParseError) -> Self {
        KrbInfraCltErr::Io {
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, err),
        }
    }
}

impl std::fmt::Debug for KrbInfraCltErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KrbInfraCltErr::Io { source } => {
                write!(f, "I/O error: {:?}", source)
            }
        }
    }
}

pub type KrbInfraCltResult<T> = Result<T, KrbInfraCltErr>;
