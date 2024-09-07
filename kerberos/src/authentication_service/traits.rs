use messages::basic_types::{EncryptionKey, Int32, PrincipalName, Realm};

pub trait PrincipalDatabase {
    fn get_client_principal_key(
        &self,
        principal_name: &PrincipalName,
        realm: Realm,
    ) -> Vec<EncryptionKey>;
    fn get_server_principal_key(
        &self,
        principal_name: &PrincipalName,
        realm: Realm,
    ) -> Vec<EncryptionKey>;

    fn get_server_supported_encryption_types(
        &self,
        principal_name: &PrincipalName,
        realm: Realm,
    ) -> Vec<Int32>;
}
