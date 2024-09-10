use crate::client::client_env::ClientEnv;
use crate::client::client_error::ClientError;
use crate::client::util::generate_nonce;
use messages::basic_types::{KerberosFlags, KerberosTime, NameTypes, PrincipalName};
use messages::flags::KdcOptionsFlag::{POSTDATED, RENEWABLE};
use messages::{AsRep, AsReq, Decode, EncAsRepPart, KdcReqBodyBuilder, KrbErrorMsg};
use std::ops::Sub;
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

    let req_body = KdcReqBodyBuilder::default()
        .cname(cname)
        .realm(server_realm)
        .sname(sname)
        .nonce(nonce)
        .till(till)
        .etype(etypes)
        .kdc_options(kdc_options);
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
    req_body.build()?;
    let as_req = AsReq::new(pa_data, req_body);
    Ok(as_req)
}

pub fn receive_as_response(
    as_req: &AsReq,
    as_rep: &AsRep,
    client_env: &impl ClientEnv,
) -> Result<(), ClientError> {
    let rep_cname = as_rep.cname();
    let rep_crealm = as_rep.crealm();
    let req_cname = as_req.req_body().cname();
    match req_cname {
        Some(cname) => {
            if cname != rep_cname {
                return Err(ClientError::ResponseDoesNotMatch(
                    "AS Response's cname does not match that of AS Request".to_string(),
                ));
            }
        }
        None => {
            return Err(ClientError::InvalidKdcReq(
                "AS Request does not contain cname".to_string(),
            ))
        }
    }
    let req_crealm = as_req.req_body().realm();
    if req_crealm != rep_crealm {
        return Err(ClientError::ResponseDoesNotMatch(
            "AS Response's realm does not match that of AS Request".to_string(),
        ));
    }

    let client_key = client_env.get_client_key(*as_rep.enc_part().etype())?;
    let crypto = client_env.get_crypto(*as_rep.enc_part().etype())?;
    let decrypted_data = crypto.decrypt(
        as_rep.enc_part().cipher().as_bytes(),
        client_key.keyvalue().as_ref(),
    )?;
    let as_rep_part = EncAsRepPart::from_der(&decrypted_data).or(Err(ClientError::DecodeError))?;
    let rep_nonce = as_rep_part.nonce();
    let req_nonce = as_req.req_body().nonce();
    if rep_nonce != req_nonce {
        return Err(ClientError::ResponseDoesNotMatch(
            "AS Response's nonce does not match that of AS Request".to_string(),
        ));
    }

    let auth_time = as_rep_part.authtime().to_unix_duration();
    let client_time = client_env.get_current_time()?;
    let is_client_earlier = client_time.le(&auth_time);
    let clock_diff = if is_client_earlier {
        auth_time.sub(client_time)
    } else {
        client_time.sub(auth_time)
    };
    client_env.set_clock_diff(clock_diff, is_client_earlier)?;

    let rep_sname = as_rep_part.sname();
    let rep_srealm = as_rep_part.srealm();
    let req_sname = as_req.req_body().sname();
    let req_srealm = as_req.req_body().realm();
    match req_sname {
        Some(sname) => {
            if sname != rep_sname {
                return Err(ClientError::ResponseDoesNotMatch(
                    "AS Response's sname does not match that of AS Request".to_string(),
                ));
            }
        }
        None => {
            return Err(ClientError::InvalidKdcReq(
                "AS Request does not contain sname".to_string(),
            ))
        }
    }
    if req_srealm != rep_srealm {
        return Err(ClientError::ResponseDoesNotMatch(
            "AS Response's realm does not match that of AS Request".to_string(),
        ));
    }

    client_env.save_as_reply(as_rep)?;
    Ok(())
}

pub fn receive_krb_error(err_msg: &KrbErrorMsg) -> Result<(), ClientError> {
    todo!()
}
