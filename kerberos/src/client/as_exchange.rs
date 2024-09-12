use crate::client::client_env::ClientEnv;
use crate::client::client_error::ClientError;
use crate::client::kdc_exchange::{receive_kdc_rep, KdcExchangeType};
use crate::client::util::generate_nonce;
use messages::basic_types::{KerberosTime, NameTypes, PrincipalName};
use messages::flags::KdcOptionsFlag::{POSTDATED, RENEWABLE};
use messages::{AsRep, AsReq, Decode, EncAsRepPart, KdcReqBodyBuilder, KrbErrorMsg};
use std::time::Duration;

pub fn prepare_as_request(
    client_env: &impl ClientEnv,
    starttime: Option<KerberosTime>,
    renewal_time: Option<KerberosTime>,
) -> Result<AsReq, ClientError> {
    let client_name = client_env.get_client_name()?;
    let cname = PrincipalName::new(NameTypes::NtPrincipal, vec![client_name])
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let server_realm = client_env.get_server_realm()?;
    let server_name = client_env.get_server_name()?;
    let sname = PrincipalName::new(NameTypes::NtPrincipal, vec![server_name])
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let nonce = generate_nonce();
    let current_time = client_env.get_current_time()?;
    let duration = Duration::new(60 * 60 * 24, 0);
    let till = KerberosTime::from_unix_duration(current_time + duration)
        .or(Err(ClientError::DecodeError))?;
    let etypes = client_env.get_supported_etypes()?;
    let kdc_options = client_env.get_kdc_options()?;
    let pa_data = Vec::new();

    let mut req_body = KdcReqBodyBuilder::default();
    let req_body = req_body
        .cname(cname)
        .realm(server_realm)
        .sname(sname)
        .nonce(nonce)
        .till(till)
        .etype(etypes)
        .kdc_options(kdc_options.clone());
    if kdc_options.is_set(POSTDATED as usize) {
        match starttime {
            None => {
                return Err(ClientError::PrepareRequestError(
                    "POSTDATED flag is set but no starttime is provided".to_string(),
                ))
            }
            Some(starttime) => {
                req_body.from(starttime);
            }
        }
    }

    if kdc_options.is_set(RENEWABLE as usize) {
        match renewal_time {
            None => {
                return Err(ClientError::PrepareRequestError(
                    "RENEWABLE flag is set but no renewal time is provided".to_string(),
                ))
            }
            Some(renewal_time) => {
                req_body.rtime(renewal_time);
            }
        }
    }
    let req_body = req_body.build()?;
    let as_req = AsReq::new(pa_data, req_body);
    Ok(as_req)
}

pub fn receive_as_response(
    client_env: &impl ClientEnv,
    as_req: &AsReq,
    as_rep: &AsRep,
) -> Result<(), ClientError> {
    let cryptosystem = client_env.get_crypto(*as_rep.enc_part().etype())?;
    let key = client_env.get_client_key(*as_rep.enc_part().etype())?;
    let decrypted_kdc_rep_part = cryptosystem.decrypt(
        as_rep.enc_part().cipher().as_ref(),
        key.keyvalue().as_ref(),
    )?;
    let enc_as_rep_part = EncAsRepPart::from_der(decrypted_kdc_rep_part.as_slice())
        .or(Err(ClientError::DecodeError))?;
    
    receive_kdc_rep(
        client_env,
        cryptosystem,
        key,
        &as_req.clone(),
        &as_rep.clone(),
        KdcExchangeType::As,
    )?;
    
    client_env.save_as_reply(as_rep, &enc_as_rep_part)?;
    Ok(())
}

pub fn receive_krb_error(err_msg: &KrbErrorMsg) -> Result<(), ClientError> {
    todo!()
}
