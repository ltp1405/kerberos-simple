use messages::basic_types::Int32;

pub trait CryptographicHash {
    fn get_checksum_type(&self) -> Int32;
    fn digest(&self, data: &[u8]) -> Vec<u8>;
}
