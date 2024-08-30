use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum CryptographyError {
    DecryptError,
    EncryptError,
    GenerateKeyError,
}

impl Display for CryptographyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptographyError::DecryptError => write!(f, "Decryption error"),
            CryptographyError::EncryptError => write!(f, "Encryption error"),
            CryptographyError::GenerateKeyError => write!(f, "Key generation error"),
        }
    }
}

impl Error for CryptographyError {}
