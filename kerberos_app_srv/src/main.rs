use std::time::Duration;

use actix_web::{
    dev::ConnectionInfo,
    web::{self},
    App, HttpResponse, HttpServer, Responder,
};
use chrono::DateTime;
use database::AppDbSchema;
use der::{asn1::OctetString, Decode, Encode};
use kerberos::application_authentication_service::ApplicationAuthenticationServiceBuilder;
use kerberos_app_srv::{
    client_address_storage::AppServerClientStorage,
    replay_cache::replay_cache::AppServerReplayCache,
    session_storage::session_storage::ApplicationSessionStorage,
};
use kerberos_infra::server::database::{
    postgres::{PgDbSettings, PostgresDb},
    Database, DbSettings, Migration,
};
use messages::{
    basic_types::{
        AddressTypes, EncryptionKey, HostAddress, KerberosString, NameTypes, PrincipalName, Realm,
    },
    ApReq,
};
use serde::{Deserialize, Serialize};
use sqlx::{Executor, Row};

#[derive(Deserialize)]
pub struct UserProfileQuery {
    pub realm: String,
    pub sequence: i32,
}

#[derive(Serialize)]
pub struct UserProfileResponse {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub firstname: String,
    pub lastname: String,
    pub birthday: DateTime<chrono::Utc>,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
pub struct UserAuthenticateCommand {
    pub tickets: Vec<u8>,
}

pub struct AuthenticationServiceConfig {
    pub realm: Realm,
    pub sname: PrincipalName,
    pub service_key: EncryptionKey,
    pub accept_empty_address_ticket: bool,
    pub ticket_allowable_clock_skew: Duration,
}

async fn handle_get(
    db: web::Data<PostgresDb>,
    auth_service_config: web::Data<AuthenticationServiceConfig>,
    replay_cache: web::Data<AppServerReplayCache>,
    session_cache: web::Data<ApplicationSessionStorage>,
    address_cache: web::Data<AppServerClientStorage>,
    query: web::Query<UserProfileQuery>,
    username: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    let username = {
        let inner = KerberosString::new(username.as_bytes()).map_err(|_| {
            actix_web::error::ErrorBadRequest(
                "Failed to create KerberosString from username".to_string(),
            )
        })?;

        PrincipalName::new(NameTypes::NtPrincipal, vec![inner])
    }
    .map_err(|_| actix_web::error::ErrorBadRequest("Failed to create PrincipalName".to_string()))?;

    let sequence_number = query.sequence;

    let realm = Realm::new(query.realm.as_bytes())
        .map_err(|_| actix_web::error::ErrorBadRequest("Failed to create Realm".to_string()))?;

    let auth_service = create_service(
        auth_service_config.as_ref(),
        replay_cache.as_ref(),
        session_cache.as_ref(),
        address_cache.as_ref(),
    );

    if auth_service
        .is_user_authenticated(&username, &realm, sequence_number)
        .await
    {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    let pool = db.inner();
    let row = pool
        .fetch_optional(
            format!(
                r#"
            SELECT * FROM "{0}".UserProfile WHERE username = '{1}';
            "#,
                db.get_schema().schema_name(),
                String::from_utf8(username.to_der().expect("Failed to encode username")).map_err(
                    |_| {
                        actix_web::error::ErrorInternalServerError(
                            "Failed to convert username to string".to_string(),
                        )
                    }
                )?
            )
            .as_str(),
        )
        .await
        .map_err(|_| {
            actix_web::error::ErrorInternalServerError("Failed to fetch user profile".to_string())
        })?;
    match row {
        Some(row) => {
            let user_profile = UserProfileResponse {
                id: row.get("id"),
                username: row.get("username"),
                email: row.get("email"),
                firstname: row.get("firstname"),
                lastname: row.get("lastname"),
                birthday: row.get("birthday"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            };
            // Return the user profile with impl Responder
            Ok(HttpResponse::Ok().json(user_profile))
        }
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

async fn handle_post(
    connection: ConnectionInfo,
    auth_service_config: web::Data<AuthenticationServiceConfig>,
    replay_cache: web::Data<AppServerReplayCache>,
    session_cache: web::Data<ApplicationSessionStorage>,
    address_cache: web::Data<AppServerClientStorage>,
    body: web::Json<UserAuthenticateCommand>,
) -> actix_web::Result<impl Responder> {
    let auth_service = create_service(
        auth_service_config.as_ref(),
        replay_cache.as_ref(),
        session_cache.as_ref(),
        address_cache.as_ref(),
    );

    let address = connection
        .peer_addr()
        .map(|addr| HostAddress::new(AddressTypes::Ipv4, OctetString::new(addr).unwrap()));

    let ap_req = ApReq::from_der(&body.tickets)
        .map_err(|_| actix_web::error::ErrorBadRequest("Failed to decode AP-REQ".to_string()))?;

    if let Some(inner) = address {
        if let Ok(address) = inner {
            address_cache.store(&ap_req, &address).await;
        } else {
            return Ok(HttpResponse::Unauthorized().finish());
        }
    } else {
        return Ok(HttpResponse::Unauthorized().finish());
    }

    let reply = auth_service.handle_krb_ap_req(ap_req).await;

    if let Ok(ap_rep) = reply {
        Ok(HttpResponse::Ok().body(ap_rep.to_der().map_err(|_| {
            actix_web::error::ErrorInternalServerError("Failed to encode AP-REP".to_string())
        })?))
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

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
            realm: Realm::new(b"EXAMPLE.COM").unwrap(),
            sname: PrincipalName::new(
                NameTypes::NtEnterprise,
                vec![KerberosString::new(b"host").unwrap()],
            )
            .unwrap(),
            service_key: EncryptionKey::new(17, OctetString::new(vec![0; 16]).unwrap()),
            accept_empty_address_ticket: true,
            ticket_allowable_clock_skew: Duration::from_secs(10),
        };
        App::new()
            .app_data(web::Data::new(replay_cache))
            .app_data(web::Data::new(session_cache))
            .app_data(web::Data::new(address_cache))
            .app_data(web::Data::new(postgres.clone()))
            .app_data(web::Data::new(auth_service_config))
            .route("/user/{username}", web::get().to(handle_get))
            .route("/authenticate", web::post().to(handle_post))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

fn create_service<'a>(
    auth_service_config: &'a AuthenticationServiceConfig,
    replay_cache: &'a AppServerReplayCache,
    session_cache: &'a ApplicationSessionStorage,
    address_cache: &'a AppServerClientStorage,
) -> kerberos::application_authentication_service::ApplicationAuthenticationService<
    'a,
    AppServerReplayCache,
    ApplicationSessionStorage,
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

mod database;
