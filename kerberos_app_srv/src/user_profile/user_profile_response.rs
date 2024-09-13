use actix_web::{body::BoxBody, dev::Service, Responder};

use crate::{handler::AppServerHandler};

use super::{error::AppServerHandlerError, user_profile::UserProfile};

pub struct UserProfileResponse {
    inner: Result<UserProfile, AppServerHandlerError>,
}

impl UserProfileResponse {
    pub fn new(inner: Result<UserProfile, AppServerHandlerError>) -> Self {
        UserProfileResponse { inner }
    }
}

impl Responder for UserProfileResponse {
    type Body = BoxBody;

    fn respond_to(self, req: &actix_web::HttpRequest) -> actix_web::HttpResponse<Self::Body> {
        match self.inner {
            Ok(user_profile) => {
                let body = serde_json::to_string(&user_profile).unwrap();
                actix_web::HttpResponse::Ok()
                    .content_type("application/json")
                    .body(body)
            }
            Err(err) => match err {
                AppServerHandlerError::UserProfileNotFound => actix_web::HttpResponse::NotFound()
                    .content_type("text/plain")
                    .body("User not found"),
                AppServerHandlerError::InvalidCredentials => {
                    actix_web::HttpResponse::Unauthorized()
                        .content_type("text/plain")
                        .body("Invalid credentials")
                }
                AppServerHandlerError::InternalServerError => {
                    actix_web::HttpResponse::InternalServerError()
                        .content_type("text/plain")
                        .body("Internal server error")
                }
            },
        }
    }
}
