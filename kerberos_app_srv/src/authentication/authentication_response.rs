use actix_web::{body::BoxBody, Responder};
use kerberos::application_authentication_service::ServerError;
use messages::{ApRep, Encode};

pub struct AuthenticationResponse {
    inner: Result<ApRep, ServerError>,
}

impl AuthenticationResponse {
    pub fn new(inner: Result<ApRep, ServerError>) -> Self {
        AuthenticationResponse { inner }
    }
}

impl Responder for AuthenticationResponse {
    type Body = BoxBody;

    fn respond_to(self, req: &actix_web::HttpRequest) -> actix_web::HttpResponse {
        match self.inner {
            Ok(ap_rep) => {
                actix_web::HttpResponse::Ok()
                    .content_type("application/json")
                    .body(ap_rep.to_der().unwrap())
            }
            Err(err) => {
                match err {
                    ServerError::Internal => {
                        actix_web::HttpResponse::InternalServerError()
                            .content_type("text/plain")
                            .body("Internal server error")
                    },
                    ServerError::ProtocolError(err_msg) => {
                        actix_web::HttpResponse::BadRequest()
                            .content_type("text/plain")
                            .body(err_msg.to_der().unwrap())
                    },
                }
            }
        }
    }
}
