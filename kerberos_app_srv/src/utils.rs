use std::time::Duration;

use kerberos::application_authentication_service::ApplicationAuthenticationServiceBuilder;
use kerberos_infra::server::cache::CacheErr;
use messages::basic_types::{EncryptionKey, PrincipalName, Realm};

use crate::{
    client_address_storage::AppServerClientStorage, replay_cache::AppServerReplayCache,
    session_storage::ApplicationSessionStorage,
};

pub enum SrvCacheError {
    MissingKey,
    Expired,
    Internal,
}

impl From<CacheErr> for SrvCacheError {
    fn from(value: CacheErr) -> Self {
        match value {
            CacheErr::MissingKey => Self::MissingKey,
            CacheErr::ValueExpired => Self::Expired,
            CacheErr::CacheFull => Self::Internal,
        }
    }
}

pub struct AuthenticationServiceConfig {
    pub realm: Realm,
    pub sname: PrincipalName,
    pub service_key: EncryptionKey,
    pub accept_empty_address_ticket: bool,
    pub ticket_allowable_clock_skew: Duration,
}

pub fn create_service<'a>(
    auth_service_config: &'a AuthenticationServiceConfig,
    replay_cache: &'a AppServerReplayCache,
    session_cache: &'a ApplicationSessionStorage,
    address_cache: &'a AppServerClientStorage,
) -> kerberos::application_authentication_service::ApplicationAuthenticationService<
    'a,
    AppServerReplayCache,
    ApplicationSessionStorage,
    AppServerClientStorage,
> {
    ApplicationAuthenticationServiceBuilder::default()
        .realm(auth_service_config.realm.clone())
        .sname(auth_service_config.sname.clone())
        .service_key(auth_service_config.service_key.clone())
        .accept_empty_address_ticket(auth_service_config.accept_empty_address_ticket)
        .ticket_allowable_clock_skew(auth_service_config.ticket_allowable_clock_skew)
        .replay_cache(replay_cache)
        .session_storage(session_cache)
        .address_storage(address_cache)
        .crypto(vec![Box::new(kerberos::AesGcm::new())])
        .build()
        .expect("Failed to build authentication service")
}
