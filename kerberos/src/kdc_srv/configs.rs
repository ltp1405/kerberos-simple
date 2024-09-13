use messages::basic_types::{PrincipalName, Realm};

use crate::{cryptographic_hash::CryptographicHash, cryptography::Cryptography};

pub struct AuthenticationServiceConfig {
    pub realm: Realm,
    pub sname: PrincipalName,
    pub require_preauth: bool,
    pub supported_crypto_systems: Vec<Box<dyn Cryptography>>,
}

impl AuthenticationServiceConfig {
    #[cfg(test)]
    pub fn local(
        require_preauth: bool,
        supported_crypto_systems: Vec<Box<dyn Cryptography>>,
    ) -> Self {
        use messages::basic_types::{KerberosString, NameTypes};

        let realm = Realm::try_from("EXAMPLE.COM").unwrap();

        let sname = PrincipalName::new(
            NameTypes::NtEnterprise,
            vec![KerberosString::try_from("host").unwrap()],
        )
        .unwrap();

        Self {
            realm,
            sname,
            require_preauth,
            supported_crypto_systems,
        }
    }
}

pub struct TicketGrantingServiceConfig {
    pub realm: Realm,
    pub sname: PrincipalName,
    pub supported_crypto_systems: Vec<Box<dyn Cryptography>>,
    pub supported_checksum_types: Vec<Box<dyn CryptographicHash>>,
}

impl TicketGrantingServiceConfig {
    #[cfg(test)]
    pub fn local(
        supported_crypto_systems: Vec<Box<dyn Cryptography>>,
        supported_checksum_types: Vec<Box<dyn CryptographicHash>>,
    ) -> Self {
        use messages::basic_types::{KerberosString, NameTypes};

        let realm = Realm::try_from("EXAMPLE.COM").unwrap();

        let sname = PrincipalName::new(
            NameTypes::NtEnterprise,
            vec![KerberosString::try_from("host").unwrap()],
        )
        .unwrap();

        Self {
            realm,
            sname,
            supported_crypto_systems,
            supported_checksum_types,
        }
    }
}
