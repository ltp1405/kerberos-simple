use crate::cryptography_error::CryptographyError;

pub trait Cryptography: Send + Sync {
    fn get_etype(&self) -> i32;

    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError>;

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError>;

    fn generate_key(&self) -> Result<Vec<u8>, CryptographyError>;

    fn clone_box(&self) -> Box<dyn Cryptography>;
}
