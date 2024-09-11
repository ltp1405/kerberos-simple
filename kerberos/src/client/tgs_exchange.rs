use crate::client::ap_exchange::prepare_ap_request;
use crate::client::client_env::ClientEnv;
use crate::client::client_env_error::ClientEnvError;
use crate::client::client_error::ClientError;
use crate::client::kdc_exchange::{receive_kdc_rep, KdcExchangeType};
use crate::client::util::generate_nonce;
use messages::basic_types::PaDataTypes::PaTgsReq;
use messages::basic_types::{
    EncryptionKey, KerberosTime, NameTypes, OctetString, PaData, PrincipalName,
};
use messages::{ApReq, Authenticator, Decode, Encode, KdcReqBodyBuilder, TgsRep, TgsReq};
use std::time::Duration;

pub fn prepare_tgs_request(client_env: &impl ClientEnv) -> Result<TgsReq, ClientError> {
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
    if etypes.is_empty() {
        return Err(ClientError::ClientEnvError(ClientEnvError {
            message: "no encryption type supported".to_string(),
        }));
    }

    // authentication header
    let ap_req = prepare_ap_request(client_env, false)?;
    let mut ap_req_buf: Vec<u8> = Vec::new();
    ap_req
        .encode_to_vec(&mut ap_req_buf)
        .or(Err(ClientError::EncodeError))?;
    let auth_header = PaData::new(
        PaTgsReq as i32,
        OctetString::new(ap_req_buf).or(Err(ClientError::EncodeError))?,
    );
    let pa_data = vec![auth_header];

    let req_body = KdcReqBodyBuilder::default()
        .cname(cname)
        .realm(server_realm)
        .sname(sname)
        .nonce(nonce)
        .kdc_options(client_env.get_kdc_options()?)
        .till(till)
        .etype(etypes)
        .build()?;
    let tgs_req = TgsReq::new(pa_data, req_body);
    Ok(tgs_req)
}

pub fn receive_tgs_response(
    tgs_req: &TgsReq,
    tgs_rep: &TgsRep,
    client_env: &impl ClientEnv,
) -> Result<(), ClientError> {
    let crypto = client_env.get_crypto(*client_env.get_tgs_reply_enc_part()?.key().keytype())?;
    let binding = client_env.get_tgs_reply_enc_part()?;
    let decrypt_key = tgs_rep
        .padata()
        .and_then(|padata| {
            padata
                .iter()
                .find(|x| *x.padata_type() == PaTgsReq as i32)
                .map(|padata| {
                    let ap_req = ApReq::from_der(padata.padata_value().as_bytes())
                        .or(Err(ClientError::DecodeError))?;
                    let decrypted_authenticator = crypto.decrypt(
                        ap_req.authenticator().cipher().as_bytes(),
                        client_env
                            .get_tgs_reply_enc_part()?
                            .key()
                            .keyvalue()
                            .as_ref(),
                    )?;
                    let authenticator = Authenticator::from_der(&decrypted_authenticator)
                        .or(Err(ClientError::DecodeError))?;
                    match authenticator.subkey() {
                        None => Ok::<EncryptionKey, ClientError>(binding.key().clone()),
                        Some(key) => Ok(key.clone()),
                    }
                })
        })
        .unwrap_or(Ok(binding.key().clone()))?;

    receive_kdc_rep(
        client_env,
        crypto,
        decrypt_key,
        tgs_req,
        tgs_rep,
        KdcExchangeType::Tgs,
    )?;

    client_env.save_tgs_reply(tgs_rep)?;
    Ok(())
}
