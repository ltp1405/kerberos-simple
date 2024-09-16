use kerberos::kdc_srv::{AuthenticationServiceConfig, Listen, TicketGrantingServiceConfig};
use kerberos::kdc_srv::npgl::NpglKdcSrv;

#[tokio::main]
async fn main() {
    let as_config = AuthenticationServiceConfig::local(false);

    let tgs_config = TicketGrantingServiceConfig::local();

    let result = NpglKdcSrv::load_from("src/bin/config", as_config, tgs_config);

    // assert!(result.is_ok(), "Failed with error: {:?}", result.err());
    result.unwrap().listen().await.unwrap();
}
