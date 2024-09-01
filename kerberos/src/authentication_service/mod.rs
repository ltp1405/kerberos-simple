#[cfg(test)]
mod tests;
mod traits;

use crate::authentication_service::traits::{KeyFinder, ReplayCache, ReplayCacheEntry};
use crate::authentication_service::ServerError::ProtocolError;
use crate::cryptography::Cryptography;
use chrono::{Local, SubsecRound};
use derive_builder::Builder;
use messages::basic_types::{
    EncryptedData, HostAddresses, Int32, KerberosTime, OctetString, PrincipalName, Realm,
};
use messages::flags::TicketFlag;
use messages::{ApRep, ApReq, Authenticator, AuthenticatorBuilder, Ecode, EncTicketPart, Encode};
use messages::{Decode, KrbErrorMsg, KrbErrorMsgBuilder};
use std::time::Duration;

#[derive(Builder)]
#[builder(pattern = "owned", setter(strip_option))]
pub struct AuthenticationService<'a, C, K, Crypto>
where
    C: ReplayCache,
    K: KeyFinder,
    Crypto: Cryptography,
{
    realm: Realm,
    sname: PrincipalName,
    accept_empty_address_ticket: bool,
    ticket_allowable_clock_skew: Duration,
    replay_cache: &'a C,
    key_finder: &'a K,
    crypto: &'a Crypto,
}

#[derive(Debug)]
enum ServerError {
    ProtocolError(KrbErrorMsg),
    Internal,
    CannotDecode,
}

pub trait PrincipalDatabase {
    fn get_client_principal_key(&self, principal_name: &PrincipalName) -> Option<String>;
    fn get_server_principal_key(&self, principal_name: &PrincipalName) -> Option<String>;
}

// fn handle_krb_as_req(db: &impl PrincipalDatabase, as_req: AsReq) -> Result<AsRep, ServerError> {
//     db.get_client_principal_key(
//         as_req
//             .req_body()
//             .cname()
//             .ok_or(ServerError::ClientPrincipalNameNotFound)?,
//     );
//
//     db.get_server_principal_key(
//         as_req
//             .req_body()
//             .cname()
//             .ok_or(ServerError::ServerPrincipalNameNotFound)?,
//     );
//     unimplemented!();
// }

impl<'a, C, K, Crypto> AuthenticationService<'a, C, K, Crypto>
where
    C: ReplayCache,
    K: KeyFinder,
    Crypto: Cryptography,
{
    fn verify_msg_type(&self, msg_type: &u8) -> Result<(), Ecode> {
        match msg_type {
            14 => Ok(()),
            _ => Err(Ecode::KRB_AP_ERR_MSG_TYPE),
        }
    }
    fn verify_key(&self, key_version: &Int32) -> Result<(), Ecode> {
        // TODO: correctly implement this
        Ok(())
    }

    fn search_for_addresses(&self, host_addresses: &HostAddresses) -> bool {
        unimplemented!()
    }

    fn get_key_for_decrypt(&self, srealm: &Realm) -> Option<Vec<u8>> {
        self.key_finder.get_key_for_srealm(srealm)
    }

    fn default_error_builder(&self) -> KrbErrorMsgBuilder {
        let now = Local::now();
        let time = now.round_subsecs(0).to_utc().timestamp();
        let usec = now.timestamp_subsec_micros();
        KrbErrorMsgBuilder::default()
            .stime(KerberosTime::now())
            .susec(usec as i32)
            .sname(self.sname.clone())
            .realm(self.realm.clone())
            .to_owned()
    }

    pub fn handle_krb_ap_req(&self, ap_req: ApReq) -> Result<ApRep, ServerError> {
        let replay_cache = self.replay_cache;
        let crypto = self.crypto;
        let mut error_msg = self.default_error_builder();

        self.verify_msg_type(ap_req.msg_type())
            .and(self.verify_key(ap_req.ticket().tkt_vno()))
            .map_err(|error_code| {
                ProtocolError(error_msg.error_code(error_code).build().unwrap())
            })?;

        let key = self
            .get_key_for_decrypt(ap_req.ticket().realm())
            .ok_or(ProtocolError(
                error_msg
                    .error_code(Ecode::KRB_AP_ERR_BADKEYVER)
                    .build()
                    .unwrap(),
            ))?;

        let decrypted_ticket = crypto
            .decrypt(ap_req.ticket().enc_part().cipher().as_bytes(), &key)
            .map_err(|_| ServerError::CannotDecode)
            .and_then(|d| EncTicketPart::from_der(&d).map_err(|_| ServerError::CannotDecode))?;
        // TODO: check for decrypted msg's integrity

        let ss_key = decrypted_ticket.key().keyvalue().as_bytes();
        let authenticator = crypto
            .decrypt(ap_req.authenticator().cipher().as_bytes(), &ss_key)
            .map_err(|_| ServerError::CannotDecode)
            .and_then(|d| {
                Authenticator::from_der(&d)
                    .inspect_err(|e| println!("{:?}", e))
                    .map_err(|_| ServerError::CannotDecode)
            })?;

        error_msg
            .ctime(authenticator.ctime().to_owned())
            .cusec(authenticator.cusec().to_owned())
            .crealm(authenticator.crealm().to_owned())
            .cname(authenticator.cname().to_owned());

        self.accept_empty_address_ticket
            .then_some(())
            .or(decrypted_ticket
                .caddr()
                .is_some_and(|t| self.search_for_addresses(t))
                .then_some(()))
            .ok_or(ProtocolError(
                error_msg
                    .error_code(Ecode::KRB_AP_ERR_BADADDR)
                    .build()
                    .unwrap(),
            ))?;

        let ticket_time = decrypted_ticket
            .starttime()
            .unwrap_or(decrypted_ticket.authtime());

        let local_time = KerberosTime::now();

        decrypted_ticket
            .flags()
            .is_set(TicketFlag::INVALID as usize)
            .then_some(ServerError::ProtocolError(
                error_msg
                    .error_code(Ecode::KRB_AP_ERR_TKT_NYV)
                    .build()
                    .unwrap(),
            ))
            .map(Err)
            .unwrap_or(Ok(()))
            .and(
                valid_ticket_time(&ticket_time, &local_time, self.ticket_allowable_clock_skew)
                    .map_err(|ecode| ProtocolError(error_msg.error_code(ecode).build().unwrap())),
            )?;

        replay_cache
            .store(ReplayCacheEntry {
                server_name: ap_req.ticket().sname().clone(),
                client_name: decrypted_ticket.cname().clone(),
                time: authenticator.ctime(),
                microseconds: authenticator.cusec(),
            })
            .map_err(|_| ServerError::Internal)?;

        let rep_authenticator = AuthenticatorBuilder::default()
            .ctime(authenticator.ctime())
            .cusec(authenticator.cusec())
            .crealm(authenticator.crealm().clone())
            .cname(authenticator.cname().clone())
            .build()
            .unwrap()
            .to_der()
            .map_err(|_| ServerError::Internal)?;

        let encrypted = crypto
            .encrypt(
                &rep_authenticator,
                decrypted_ticket.key().keyvalue().as_bytes(),
            )
            .map_err(|_| ServerError::Internal)?;

        Ok(ApRep::new(EncryptedData::new(
            *ap_req.ticket().enc_part().etype(),
            ap_req.ticket().enc_part().kvno().map(|v| *v),
            OctetString::new(encrypted).map_err(|_| ServerError::Internal)?,
        )))

        // NOTE: Sequence number in authenticator is not handled because we do not
        // implement KRB_PRIV or KRB_SAFE
    }
}

fn valid_ticket_time(
    ticket_time: &KerberosTime,
    local_time: &KerberosTime,
    server_allow_clock_skew: Duration,
) -> Result<(), Ecode> {
    let local_time = local_time.to_unix_duration();
    let ticket_time = ticket_time.to_unix_duration();
    if local_time > ticket_time {
        let skew = local_time - ticket_time;
        if skew > server_allow_clock_skew {
            return Err(Ecode::KRB_AP_ERR_TKT_NYV);
        }
    } else {
        let skew = ticket_time - local_time;
        if skew > server_allow_clock_skew {
            return Err(Ecode::KRB_AP_ERR_TKT_EXPIRED);
        }
    };
    Ok(())
}
