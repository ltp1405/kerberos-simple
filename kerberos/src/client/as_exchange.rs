use crate::client::client_env::ClientEnv;
use crate::client::util::generate_nonce;
use messages::basic_types::{KerberosTime, NameTypes, PrincipalName};
use messages::{AsReq, KdcReqBodyBuilder};

pub fn prepare_as_request(client_env: &impl ClientEnv) -> Result<AsReq, Err> {
    let client_name = client_env.get_client_name()?;
    let cname = PrincipalName::new(NameTypes::NtPrincipal, vec![client_name]);
    let server_realm = client_env.get_server_realm()?;
    let server_name = client_env.get_server_name()?;
    let sname = PrincipalName::new(NameTypes::NtPrincipal, vec![server_name]);
    let nonce = generate_nonce();
    let current_time = client_env.get_current_time()?;
    let duration = KerberosTime::from(60 * 60 * 24);
    let till = KerberosTime::from_unix_duration(
        current_time.to_unix_duration() + duration.to_unix_duration(),
    )?;
    let etypes = client_env.get_supported_etypes()?;
    let pa_data = Vec::new();
    let req_body = KdcReqBodyBuilder::default()
        .cname(cname)
        .realm(server_realm)
        .sname(sname)
        .nonce(nonce)
        .till(till)
        .etype(etypes)
        .build()?;
    let as_req = AsReq::new(pa_data, req_body);
    Ok(as_req)
}
