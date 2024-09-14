use std::sync::Arc;

use actix_web::{web, FromRequest};
use kerberos_infra::server::database::postgres::PostgresDb;
use messages::basic_types::{PrincipalName, Realm};
use serde::Serialize;
use tokio::sync::futures;

pub struct UserProfileRequest {
    username: PrincipalName,
    realm: Realm,
    sequence_number: i32
}

impl UserProfileRequest {
    pub fn new(username: PrincipalName, realm: Realm, sequence_number: i32) -> Self {
        Self { username, realm, sequence_number }
    }

    pub fn username(&self) -> &PrincipalName {
        &self.username
    }

    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    pub fn sequence_number(&self) -> i32 {
        self.sequence_number
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
        let realm = req.match_info().get("realm").unwrap().to_string();

        let sequence_number = req.match_info().get("sequence_number").unwrap();
        let sequence_number = sequence_number.parse::<i32>().unwrap();
        futures_util::future::ready(Ok(UserProfileRequest { username, realm, sequence_number }))
    }
}
