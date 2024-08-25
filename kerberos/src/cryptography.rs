pub trait Cryptography {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;

    fn decrypt(&self, data: &[u8]) -> Vec<u8>;

    fn generate_key(&self) -> Vec<u8>;
}