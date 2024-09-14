use crate::kdc_srv::{
    configs::{AuthenticationServiceConfig, TicketGrantingServiceConfig},
    npgl::NpglKdcSrv,
    Listen,
};

#[tokio::main]
async fn main() {
    let as_config = AuthenticationServiceConfig::local(false);

    let tgs_config = TicketGrantingServiceConfig::local();

    let result = NpglKdcSrv::load_from("src/kdc_srv/tests/config", as_config, tgs_config);

    // assert!(result.is_ok(), "Failed with error: {:?}", result.err());
    result.unwrap().listen().await.unwrap();
}
