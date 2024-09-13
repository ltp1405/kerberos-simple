use std::sync::Arc;

use actix_web::{web, Responder};
use async_trait::async_trait;
use kerberos_infra::server::database::postgres::PostgresDb;
use messages::ApReq;

use crate::{
    authentication::{
        authentication_request::AuthenticationRequest,
        authentication_response::AuthenticationResponse,
    },
    user_profile::{
        user_profile_request::UserProfileRequest, user_profile_response::UserProfileResponse,
    },
};

#[async_trait]
pub trait Handleable {
    async fn get_user_profile(&self, request: UserProfileRequest) -> UserProfileResponse;

    async fn authenticate(&self, request: AuthenticationRequest) -> AuthenticationResponse;
}
