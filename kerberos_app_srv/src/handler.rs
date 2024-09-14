use std::sync::Arc;

use actix_web::{http::header::Date, web, Responder};
use async_trait::async_trait;
use kerberos::{
    application_authentication_service::{
        ApplicationAuthenticationService, ApplicationAuthenticationServiceBuilder,
    },
    authentication_service::AuthenticationService,
    service_traits::ApReplayCache,
};
use kerberos_infra::server::database::{postgres::PostgresDb, Database};
use messages::ApReq;
use sqlx::{pool, Executor, Row};

use crate::{
    auth_cache::{self, auth_cache::ApplicationAuthenticationCache}, authentication::{
        authentication_request::AuthenticationRequest,
        authentication_response::AuthenticationResponse,
    }, handleable::Handleable, replay_cache::replay_cache::AppServerReplayCache, user_profile::{
        error::AppServerHandlerError, user_profile::UserProfile, user_profile_request::UserProfileRequest, user_profile_response::UserProfileResponse
    }
};

pub struct AppServerHandler<'a> {
    db: Arc<PostgresDb>,
    auth_service: ApplicationAuthenticationService<'a, AppServerReplayCache>,
    auth_cache: ApplicationAuthenticationCache
}

unsafe impl<'a> Sync for AppServerHandler<'a> {}

impl<'a> AppServerHandler<'a> {
    pub fn new(
        db: Arc<PostgresDb>,
        auth_service: ApplicationAuthenticationService<'a, AppServerReplayCache>,
        auth_cache: ApplicationAuthenticationCache,
    ) -> Self {
        Self { db, auth_service, auth_cache }
    }

}
#[async_trait]
impl<'a> Handleable for AppServerHandler<'a> {
    async fn get_user_profile(&self, request: UserProfileRequest) -> UserProfileResponse {
        let username = request.username();
        let sequence_number = request.sequence_number();
        if !self.auth_cache.contains(username, sequence_number).await {
            return UserProfileResponse::new(Err(AppServerHandlerError::UserIsNotAuthorized));
        }
        let pool = self.db.inner();
        let row = pool
            .fetch_optional(
                format!(
                    r#"
            SELECT * FROM "{0}".UserProfile WHERE username = '{1}';
            "#,
                    self.db.get_schema().schema_name(),
                    username
                )
                .as_str(),
            )
            .await
            .expect("Failed to fetch user profile");
        match row {
            Some(row) => {
                let user_profile = UserProfile {
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
                UserProfileResponse::new(Ok(user_profile))
            }
            None => UserProfileResponse::new(Err(AppServerHandlerError::UserProfileNotFound)),
        }
    }

    async fn authenticate(&self, request: AuthenticationRequest) -> AuthenticationResponse {
        AuthenticationResponse::new(self.auth_service.handle_krb_ap_req(request.ap_req()).await)
    }
}
