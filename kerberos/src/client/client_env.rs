use crate::client::client_env_error::ClientEnvError;
use crate::cryptographic_hash::CryptographicHash;
use crate::cryptography::Cryptography;
use messages::basic_types::{EncryptionKey, KerberosFlags, KerberosString, KerberosTime};
use messages::{AsRep, EncAsRepPart, EncTgsRepPart, TgsRep};
use std::time::Duration;

pub trait ClientEnv {
    fn get_client_name(&self) -> Result<KerberosString, ClientEnvError>;

    fn get_client_realm(&self) -> Result<KerberosString, ClientEnvError>;

    fn get_server_name(&self) -> Result<KerberosString, ClientEnvError>;

    fn get_server_realm(&self) -> Result<KerberosString, ClientEnvError>;

    fn get_kdc_options(&self) -> Result<KerberosFlags, ClientEnvError>;

    fn get_current_time(&self) -> Result<Duration, ClientEnvError> {
        Ok(KerberosTime::now().to_unix_duration())
    }

    fn get_supported_etypes(&self) -> Result<Vec<i32>, ClientEnvError>;

    fn get_crypto(&self, etype: i32) -> Result<Box<dyn Cryptography>, ClientEnvError>;
    fn get_checksum_hash(
        &self,
        checksum_type: i32,
    ) -> Result<Box<dyn CryptographicHash>, ClientEnvError>;
    fn get_supported_checksums(&self) -> Result<Vec<i32>, ClientEnvError>;

    fn get_client_key(&self, key_type: i32) -> Result<EncryptionKey, ClientEnvError>;

    fn set_clock_diff(&self, diff: Duration, is_client_earlier: bool)
        -> Result<(), ClientEnvError>;

    fn save_as_reply(&self, data: &AsRep, data_part: &EncAsRepPart) -> Result<(), ClientEnvError>;

    fn get_as_reply(&self) -> Result<AsRep, ClientEnvError>;

    fn get_as_reply_enc_part(&self) -> Result<EncAsRepPart, ClientEnvError>;

    fn save_tgs_reply(
        &self,
        data: &TgsRep,
        data_part: &EncTgsRepPart,
    ) -> Result<(), ClientEnvError>;

    fn get_tgs_reply(&self) -> Result<TgsRep, ClientEnvError>;

    fn get_tgs_reply_enc_part(&self) -> Result<EncTgsRepPart, ClientEnvError>;

    fn save_subkey(&self, key: EncryptionKey) -> Result<(), ClientEnvError>;

    fn save_seq_number(&self, seq_num: u32) -> Result<(), ClientEnvError>;
}
