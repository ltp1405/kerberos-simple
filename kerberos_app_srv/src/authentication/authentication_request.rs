use actix_web::{FromRequest, HttpMessage};
use messages::ApReq;

pub struct AuthenticationRequest {
    ap_req: ApReq,
}

impl AuthenticationRequest {
    pub fn new(ap_req: ApReq) -> Self {
        Self { ap_req }
    }
    pub fn ap_req(&self) -> ApReq {
        self.ap_req.clone()
    }
}

impl FromRequest for AuthenticationRequest {
    type Error = actix_web::Error;
    type Future = futures_util::future::Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let ap_req = req.extensions().get::<ApReq>().unwrap().clone();
        futures_util::future::ready(Ok(AuthenticationRequest { ap_req }))
    }
}
