pub trait Cryptography {
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, Err>;

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, Err>;

    fn generate_key(&self) -> Result<Vec<u8>, Err>;
}
