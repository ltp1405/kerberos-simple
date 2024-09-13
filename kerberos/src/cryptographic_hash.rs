use messages::basic_types::Int32;

pub trait CryptographicHash: Send + Sync {
    fn get_checksum_type(&self) -> Int32;
    fn digest(&self, data: &[u8]) -> Vec<u8>;
}
