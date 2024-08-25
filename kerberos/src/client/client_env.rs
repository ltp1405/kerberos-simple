use messages::basic_types::{KerberosTime, OctetString};
use std::fmt::{Debug, Display, Pointer};
use crate::client::client_env_error::ClientEnvError;

pub trait ClientEnv {
    fn get_client_name(&self) -> Result<OctetString, ClientEnvError>;

    fn get_client_realm(&self) -> Result<OctetString, ClientEnvError>;

    fn get_server_name(&self) -> Result<OctetString, ClientEnvError>;

    fn get_server_realm(&self) -> Result<OctetString, ClientEnvError>;

    fn get_client_address(&self) -> Result<OctetString, ClientEnvError>;

    fn get_current_time(&self) -> Result<KerberosTime, ClientEnvError>;
}
