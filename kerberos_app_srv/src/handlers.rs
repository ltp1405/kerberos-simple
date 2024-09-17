use actix_web::{dev::ConnectionInfo, web, HttpResponse, Responder};
use chrono::DateTime;
use der::{Decode, Encode};
use kerberos_infra::server::database::{postgres::PostgresDb, Database};
use messages::{
    basic_types::{
        AddressTypes, HostAddress, KerberosString, NameTypes, OctetString, PrincipalName, Realm,
    },
    ApReq,
};
use serde::{Deserialize, Serialize};
use sqlx::{Executor, Row};

use crate::{
    client_address_storage::AppServerClientStorage,
    replay_cache::AppServerReplayCache,
    session_storage::ApplicationSessionStorage,
    utils::{create_service, AuthenticationServiceConfig},
};

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

#[actix_web::get("/users/{username}")]
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

    let username = username.name_string().first().map(|o| o.as_str()).ok_or(
        actix_web::error::ErrorBadRequest("Failed to get username from PrincipalName".to_string()),
    )?;

    let pool = db.inner();

    let row = pool
        .fetch_optional(
            format!(
                r#"
                SELECT id, username, email, firstname, lastname, birthday, created_at, updated_at
                FROM "{0}".UserProfile
                WHERE username = '{1}';
            "#,
                db.get_schema().schema_name(),
                username
            )
            .as_str(),
        )
        .await
        .map_err(|_| {
            actix_web::error::ErrorInternalServerError("Failed to fetch user profile".to_string())
        })?;

    let body = row
        .map(|inner| UserProfileResponse {
            id: inner.get("id"),
            username: inner.get("username"),
            email: inner.get("email"),
            firstname: inner.get("firstname"),
            lastname: inner.get("lastname"),
            birthday: inner.get("birthday"),
            created_at: inner.get("created_at"),
            updated_at: inner.get("updated_at"),
        })
        .ok_or(actix_web::error::ErrorNotFound(
            "User not found".to_string(),
        ))?;

    Ok(HttpResponse::Ok().json(body))
}

#[actix_web::post("/authenticate")]
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
