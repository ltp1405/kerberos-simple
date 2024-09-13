use std::vec;

use crate::kdc_srv::{
    configs::{AuthenticationServiceConfig, TicketGrantingServiceConfig},
    npgl::NpglKdcSrv,
    Listen,
};

#[tokio::test]
async fn kdc_is_spawned_when_loading_config_from_the_right_location() {
    let as_config = AuthenticationServiceConfig::local(false, vec![]);

    let tgs_config = TicketGrantingServiceConfig::local(vec![], vec![]);

    let result = NpglKdcSrv::load_from("src/npgl_kdc_server/tests/configs", as_config, tgs_config);

    assert!(result.is_ok(), "Failed with error: {:?}", result.err());
}

#[tokio::test]
async fn kdc_is_spawned_when_loading_config_from_default_dir() {
    let as_config = AuthenticationServiceConfig::local(false, vec![]);

    let tgs_config = TicketGrantingServiceConfig::local(vec![], vec![]);

    let result = NpglKdcSrv::load_from_dir(as_config, tgs_config);

    assert!(result.is_ok(), "Failed with error: {:?}", result.err());
}
