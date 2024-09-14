use async_trait::async_trait;
use crate::authentication::{
    authentication_request::AuthenticationRequest, authentication_response::AuthenticationResponse,
};

#[async_trait]
pub trait Handleable {
    // async fn get_user_profile(&self, request: UserProfileRequest) -> UserProfileResponse;

    async fn authenticate(&self, request: AuthenticationRequest) -> AuthenticationResponse;
}
