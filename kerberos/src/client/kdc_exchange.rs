use crate::client::client_env::ClientEnv;
use crate::client::client_error::ClientError;
use crate::client::client_error::ClientError::{ClockSkewError, InvalidKdcReq, ResponseModified};
use crate::client::util::{is_within_clock_skew, is_zero_time};
use crate::cryptography::Cryptography;
use messages::basic_types::{EncryptionKey, KerberosTime};
use messages::flags::KdcOptionsFlag::{RENEWABLE, RENEWABLE_OK};
use messages::{Decode, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcRep, KdcReq};
use std::time::Duration;

pub(crate) enum KdcExchangeType {
    As,
    Tgs,
}

pub fn receive_kdc_rep(
    client_env: &impl ClientEnv,
    cryptography: Box<dyn Cryptography>,
    encryption_key: EncryptionKey,
    kdc_req: &KdcReq,
    kdc_rep: &KdcRep,
    exchange_type: KdcExchangeType,
) -> Result<(), ClientError> {
    let decrypted_kdc_rep_part = cryptography.decrypt(
        kdc_rep.enc_part().cipher().as_ref(),
        encryption_key.keyvalue().as_ref(),
    )?;

    let kdc_rep_part: EncKdcRepPart = match exchange_type {
        KdcExchangeType::As => {
            EncAsRepPart::from_der(decrypted_kdc_rep_part.as_slice())
                .or(Err(ClientError::DecodeError))?
                .0
        }
        KdcExchangeType::Tgs => {
            EncTgsRepPart::from_der(decrypted_kdc_rep_part.as_slice())
                .or(Err(ClientError::DecodeError))?
                .0
        }
    };
    let req_cname = kdc_req
        .req_body()
        .cname()
        .ok_or(InvalidKdcReq("Request cname not found".to_string()))?;
    let req_sname = kdc_req
        .req_body()
        .sname()
        .ok_or(InvalidKdcReq("Request sname not found".to_string()))?;
    if *req_cname != *kdc_rep.cname()
        || *kdc_rep.crealm() != *kdc_req.req_body().realm()
        || req_sname != kdc_rep_part.sname()
        || kdc_req.req_body().realm() != kdc_rep_part.srealm()
        || kdc_req.req_body().nonce() != kdc_rep_part.nonce()
        || kdc_req.req_body().addresses() != kdc_rep_part.caddr()
    {
        return Err(ResponseModified);
    }

    if kdc_req.req_body().kdc_options() != kdc_rep_part.flags() {
        return Err(ResponseModified);
    }

    if kdc_req.req_body().from().is_none()
        && !is_within_clock_skew(
            kdc_rep_part
                .starttime()
                .ok_or(ResponseModified)?
                .to_unix_duration(),
            client_env.get_current_time()?,
            Duration::from_secs(5 * 60),
        )
    {
        return Err(ClockSkewError);
    }

    if let Some(starttime) = kdc_rep_part.starttime() {
        if kdc_req.req_body().from().is_some() && kdc_req.req_body().from().unwrap() != starttime {
            return Err(ResponseModified);
        }
    } else {
        return Err(ResponseModified);
    }

    if kdc_req.req_body().till()
        != &KerberosTime::from_unix_duration(Duration::from_secs(0)).unwrap()
        && kdc_rep_part.endtime() > kdc_req.req_body().till()
    {
        return Err(ResponseModified);
    }

    if kdc_req.req_body().kdc_options().is_set(RENEWABLE as usize)
        && kdc_req.req_body().rtime().is_some()
        && !is_zero_time(*kdc_req.req_body().rtime().unwrap())
        && kdc_rep_part.renew_till().is_some()
        && kdc_rep_part.renew_till().unwrap() > kdc_req.req_body().rtime().unwrap()
    {
        return Err(ResponseModified);
    }

    if kdc_req
        .req_body()
        .kdc_options()
        .is_set(RENEWABLE_OK as usize)
        && kdc_rep_part.flags().is_set(RENEWABLE as usize)
        && !is_zero_time(*kdc_req.req_body().till())
        && kdc_rep_part.renew_till().is_some()
        && kdc_rep_part.renew_till().unwrap() > kdc_req.req_body().till()
    {
        return Err(ResponseModified);
    }
    Ok(())
}
