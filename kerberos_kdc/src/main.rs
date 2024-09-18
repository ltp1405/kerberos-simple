extern crate kerberos;
extern crate messages;

use kerberos_kdc::kdc_srv::{AuthenticationServiceConfig, Listen, TicketGrantingServiceConfig};
use kerberos_kdc::kdc_srv::npgl::NpglKdcSrv;
use messages::basic_types::{KerberosString, NameTypes, PrincipalName, Realm};

#[tokio::main]
async fn main() {
    let realm = Realm::try_from("EXAMPLE.COM").unwrap();

    let sname = PrincipalName::new(
        NameTypes::NtEnterprise,
        vec![KerberosString::try_from("host").unwrap()],
    )
    .unwrap();
    let as_config = AuthenticationServiceConfig {
        realm: realm.clone(),
        sname: sname.clone(),
        require_preauth: false,
    };

    let tgs_config = TicketGrantingServiceConfig { realm, sname };

    let mut kdc =
        NpglKdcSrv::load_from("config", as_config, tgs_config).expect("Failed to load KDC");

    kdc.listen().await.expect("Failed to run KDC");
}
