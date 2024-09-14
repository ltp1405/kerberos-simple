use std::sync::Arc;

use actix_web::{web, FromRequest};
use kerberos_infra::server::database::postgres::PostgresDb;
use serde::Serialize;
use tokio::sync::futures;

pub struct UserProfileRequest {
    username: String,
    sequence_number: Vec<u8>
}

impl UserProfileRequest {
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn sequence_number(&self) -> Vec<u8> {
        self.sequence_number.clone()
    }
}

impl FromRequest for UserProfileRequest {
    type Error = actix_web::Error;
    type Future = futures_util::future::Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let username = req.match_info().get("username").unwrap().to_string();
        let sequence_number = req.match_info().get("sequence_number").unwrap().to_string().as_bytes().to_vec();
        futures_util::future::ready(Ok(UserProfileRequest { username, sequence_number }))
    }
}
