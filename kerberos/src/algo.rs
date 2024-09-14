use crate::cryptographic_hash::CryptographicHash;
use crate::cryptography::Cryptography;
use crate::cryptography_error::CryptographyError;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::aes::Aes256;
use aes_gcm::KeyInit;
use messages::basic_types::Int32;
use sha1;
use sha1::Digest;

pub struct AesGcm;

impl AesGcm {
    pub fn new() -> Self {
        Self
    }
}

impl Cryptography for AesGcm {
    fn get_etype(&self) -> i32 {
        1
    }

    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        if key.len() != 32 {
            return Err(CryptographyError::WrongKeySize);
        }
        let key = aes_gcm::Key::<Aes256>::from_slice(key);
        let nonce = aes_gcm::Nonce::from([0xff; 12]);
        let cipher = aes_gcm::Aes256Gcm::new(&key);
        Ok(cipher.encrypt(&nonce, data).unwrap().to_vec())
    }

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        if key.len() != 32 {
            return Err(CryptographyError::WrongKeySize);
        }
        let key = aes_gcm::Key::<Aes256>::from_slice(key);
        let nonce = aes_gcm::Nonce::from([0xff; 12]);
        let cipher = aes_gcm::Aes256Gcm::new(&key);
        Ok(cipher.decrypt(&nonce, data).unwrap().to_vec())
    }

    fn generate_key(&self) -> Result<Vec<u8>, CryptographyError> {
        Ok(aes_gcm::Aes256Gcm::generate_key(OsRng).to_vec())
    }
}

pub struct Sha1;

impl Sha1 {
    pub fn new() -> Self {
        Self
    }
}

impl CryptographicHash for Sha1 {
    fn get_checksum_type(&self) -> Int32 {
        1
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = sha1::Sha1::default();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::algo::{AesGcm, Sha1};
    use crate::cryptographic_hash::CryptographicHash;
    use crate::cryptography::Cryptography;

    #[test]
    fn test_encrypt_decrypt() {
        let algo = AesGcm::new();
        let data = vec![0xff; 12];
        let encrypted = algo.encrypt(&data, &[0xff; 32]).unwrap();
        let decrypted = algo.decrypt(&encrypted, &[0xff; 32]).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_wrong_key_size() {
        let algo = AesGcm::new();
        let data = vec![0xff; 12];
        let key = vec![0xff; 12];
        let encrypted = algo
            .encrypt(&data, &key)
            .expect_err("Should fail, wrong key size");
        let decrypted = algo
            .decrypt(&[1u8; 12], &key)
            .expect_err("Should fail, wrong key size");
    }

    #[test]
    fn test_hash() {
        let hasher = Sha1::new();
        let data = vec![0xff; 12];
        let digested = hasher.digest(&data);
        assert_eq!(digested.len(), 160 / 8);
        assert_ne!(data, digested);
    }
}
