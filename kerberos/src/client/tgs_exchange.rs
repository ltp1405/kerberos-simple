use crate::client::ap_exchange::prepare_ap_request;
use crate::client::client_env::ClientEnv;
use crate::client::client_error::ClientError;
use crate::client::util::generate_nonce;
use crate::cryptography::Cryptography;
use messages::basic_types::{KerberosTime, NameTypes, OctetString, PaData, PrincipalName};
use messages::{Encode, KdcReqBodyBuilder, TgsReq};
use std::time::Duration;
use messages::basic_types::PaDataTypes::PaTgsReq;

pub fn prepare_tgs_request(
    client_env: impl ClientEnv,
    cryptography: impl Cryptography,
) -> Result<TgsReq, ClientError> {
    let client_name = client_env.get_client_name()?;
    let server_realm = client_env.get_server_realm()?;
    let server_name = client_env.get_server_name()?;
    let sname = PrincipalName::new(NameTypes::NtPrincipal, vec![server_name])
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let cname = PrincipalName::new(NameTypes::NtPrincipal, vec![client_name])
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let nonce = generate_nonce();
    let current_time = client_env.get_current_time()?;
    let duration = Duration::new(60 * 60 * 24, 0);
    let till = KerberosTime::from_unix_duration(current_time + duration)
        .or(Err(ClientError::DecodeError))?;
    let etypes = client_env.get_supported_etypes()?;

    // authentication header
    let ap_req = prepare_ap_request(&client_env, &cryptography, false)?;
    let mut ap_req_buf: Vec<u8> = Vec::new();
    ap_req
        .encode_to_vec(&mut ap_req_buf)
        .or(Err(ClientError::EncodeError))?;
    let auth_header = PaData::new(
        PaTgsReq as i32, // PaTgsReq
        OctetString::new(ap_req_buf).or(Err(ClientError::EncodeError))?,
    );
    let pa_data = vec![auth_header];

    let req_body = KdcReqBodyBuilder::default()
        .cname(cname)
        .realm(server_realm)
        .sname(sname)
        .nonce(nonce)
        .till(till)
        .etype(etypes)
        .build()?;
    let tgs_req = TgsReq::new(pa_data, req_body);
    Ok(tgs_req)
}
