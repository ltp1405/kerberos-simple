use std::time::Duration;

use actix_web::{
    web::{self},
    App, HttpServer,
};
use der::asn1::OctetString;
use kerberos_app_srv::{
    client_address_storage::AppServerClientStorage, replay_cache::AppServerReplayCache,
    session_storage::ApplicationSessionStorage,
};
use kerberos_app_srv::{
    database::AppDbSchema,
    handlers::{handle_get, handle_post},
    utils::AuthenticationServiceConfig,
};
use kerberos_infra::server::database::{
    postgres::{PgDbSettings, PostgresDb},
    DbSettings, Migration,
};
use messages::basic_types::{EncryptionKey, KerberosString, NameTypes, PrincipalName, Realm};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = PgDbSettings::load_from_dir();

    let schema = AppDbSchema::boxed();

    let mut postgres = PostgresDb::new(config, schema);

    postgres.migrate_then_seed().await.unwrap();

    HttpServer::new(move || {
        let replay_cache = AppServerReplayCache::new();
        let session_cache = ApplicationSessionStorage::new();
        let address_cache = AppServerClientStorage::new();
        let auth_service_config = AuthenticationServiceConfig {
            realm: Realm::new(b"MYREALM.COM").unwrap(),
            sname: PrincipalName::new(
                NameTypes::NtEnterprise,
                vec![KerberosString::new(b"MYREALM.COM").unwrap()],
            )
            .unwrap(),
            service_key: EncryptionKey::new(
                1,
                OctetString::new(b"M4rYnBn0kOQC5vM1ddnAHXcKc0hhe16d").unwrap(),
            ),
            accept_empty_address_ticket: true,
            ticket_allowable_clock_skew: Duration::from_secs(10),
        };
        App::new()
            .app_data(web::Data::new(replay_cache))
            .app_data(web::Data::new(session_cache))
            .app_data(web::Data::new(address_cache))
            .app_data(web::Data::new(postgres.clone()))
            .app_data(web::Data::new(auth_service_config))
            .service(handle_get)
            .service(handle_post)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
