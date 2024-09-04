use messages::basic_types::{EncryptionKey, KerberosString, OctetString};
use std::fmt::{Debug, Display, Pointer};
use std::time::Duration;
use messages::AsRep;
use crate::client::client_env_error::ClientEnvError;

pub trait ClientEnv {
    fn get_client_name(&self) -> Result<KerberosString, ClientEnvError>;

    fn get_client_realm(&self) -> Result<KerberosString, ClientEnvError>;

    fn get_server_name(&self) -> Result<KerberosString, ClientEnvError>;

    fn get_server_realm(&self) -> Result<KerberosString, ClientEnvError>;

    fn get_client_address(&self) -> Result<OctetString, ClientEnvError>;

    fn get_current_time(&self) -> Result<Duration, ClientEnvError>;

    fn get_supported_etypes(&self) -> Result<Vec<i32>, ClientEnvError>;

    fn get_client_key(&self, key_type: i32) -> Result<EncryptionKey, ClientEnvError>;

    fn set_clock_diff(&self, diff: Duration, is_client_earlier: bool) -> Result<(), ClientEnvError>;

    fn save_as_reply(&self, data: &AsRep) -> Result<(), ClientEnvError>;

    fn get_as_reply(&self) -> Result<AsRep, ClientEnvError>;
}
