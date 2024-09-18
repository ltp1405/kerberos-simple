use std::time::Duration;

use actix_web::{
    web::{self},
    App, HttpServer,
};
use config::Config;
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
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut postgres = {
        let db_config = PgDbSettings::load("server");

        let schema = AppDbSchema::boxed();

        PostgresDb::new(db_config, schema)
    };

    postgres.migrate_then_seed().await.unwrap();

    HttpServer::new(move || {
        let replay_cache = AppServerReplayCache::new();
        let session_cache = ApplicationSessionStorage::new();
        let address_cache = AppServerClientStorage::new();
        let app_config = AppSrvConfig::load_from("server");
        let auth_service_config = AuthenticationServiceConfig::from(app_config);
        println!("Application server started at 127.0.0.1:8080!");
        App::new()
            .app_data(web::Data::new(replay_cache))
            .app_data(web::Data::new(session_cache))
            .app_data(web::Data::new(address_cache))
            .app_data(web::Data::new(postgres.clone()))
            .app_data(web::Data::new(auth_service_config))
            .service(handle_get)
            .service(handle_post)
            
    })
    .workers(1)
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[derive(Debug, Deserialize)]
pub struct AppSrvConfig {
    pub realm: SecretBox<String>,
    pub sname: SecretBox<String>,
    pub service_key: SecretBox<String>,
    pub accept_empty_address_ticket: bool,
    pub ticket_allowable_clock_skew: u64,
}

impl AppSrvConfig {
    pub fn load_from(dir: &str) -> Self {
        let base_path = std::env::current_dir().expect("Fail to read the base directory");

        let config = base_path.join(dir);

        Config::builder()
            .add_source(config::File::from(config.join("base")))
            .build()
            .unwrap()
            .into()
    }
}

impl From<AppSrvConfig> for AuthenticationServiceConfig {
    fn from(value: AppSrvConfig) -> Self {
        AuthenticationServiceConfig {
            realm: Realm::new(value.realm.expose_secret()).unwrap(),
            sname: PrincipalName::new(
                NameTypes::NtEnterprise,
                vec![KerberosString::new(value.sname.expose_secret()).unwrap()],
            )
            .unwrap(),
            service_key: EncryptionKey::new(
                1,
                OctetString::new(value.service_key.expose_secret().clone()).unwrap(),
            ),
            accept_empty_address_ticket: value.accept_empty_address_ticket,
            ticket_allowable_clock_skew: Duration::from_secs(value.ticket_allowable_clock_skew),
        }
    }
}

impl From<Config> for AppSrvConfig {
    fn from(value: Config) -> Self {
        value
            .get::<Self>("server")
            .expect("Failed to load AppSrvConfig from Config")
    }
}
