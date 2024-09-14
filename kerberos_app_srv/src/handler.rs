use std::sync::Arc;
use async_trait::async_trait;
use kerberos::application_authentication_service::ApplicationAuthenticationService;
use kerberos_infra::server::database::{postgres::PostgresDb, Database};
use sqlx::{Executor, Row};

use crate::{
    authentication::{
        authentication_request::AuthenticationRequest,
        authentication_response::AuthenticationResponse,
    },
    handleable::Handleable,
    replay_cache::replay_cache::AppServerReplayCache,
    session_storage::session_storage::ApplicationSessionStorage,
};

pub struct AppServerHandler<'a> {
    db: Arc<PostgresDb>,
    auth_service:
        ApplicationAuthenticationService<'a, AppServerReplayCache, ApplicationSessionStorage>,
}

unsafe impl<'a> Sync for AppServerHandler<'a> {}

impl<'a> AppServerHandler<'a> {
    pub fn new(
        db: Arc<PostgresDb>,
        auth_service: ApplicationAuthenticationService<
            'a,
            AppServerReplayCache,
            ApplicationSessionStorage,
        >,
    ) -> Self {
        Self { db, auth_service }
    }
}
// #[async_trait]
// impl<'a> Handleable for AppServerHandler<'a> {
//     async fn get_user_profile(&self, request: UserProfileRequest) -> UserProfileResponse {
//         let username = request.username();
//         let sequence_number = request.sequence_number();
//         let realm = request.realm();
//         if !self
//             .auth_service
//             .is_user_authenticated(username, realm, sequence_number)
//             .await
//         {
//             return UserProfileResponse::new(Err(AppServerHandlerError::UserIsNotAuthorized));
//         }
//         let pool = self.db.inner();
//         let row = pool
//             .fetch_optional(
//                 format!(
//                     r#"
//             SELECT * FROM "{0}".UserProfile WHERE username = '{1}';
//             "#,
//                     self.db.get_schema().schema_name(),
//                     String::from_utf8(username.to_der().expect("Failed to encode username"))
//                         .expect("Failed to convert username to string")
//                 )
//                 .as_str(),
//             )
//             .await
//             .expect("Failed to fetch user profile");
//         match row {
//             Some(row) => {
//                 let user_profile = UserProfile {
//                     id: row.get("id"),
//                     username: row.get("username"),
//                     email: row.get("email"),
//                     firstname: row.get("firstname"),
//                     lastname: row.get("lastname"),
//                     birthday: row.get("birthday"),
//                     created_at: row.get("created_at"),
//                     updated_at: row.get("updated_at"),
//                 };
//                 // Return the user profile with impl Responder
//                 UserProfileResponse::new(Ok(user_profile))
//             }
//             None => UserProfileResponse::new(Err(AppServerHandlerError::UserProfileNotFound)),
//         }
//     }

//     async fn authenticate(&self, request: AuthenticationRequest) -> AuthenticationResponse {
//         AuthenticationResponse::new(self.auth_service.handle_krb_ap_req(request.ap_req()).await)
//     }
// }
