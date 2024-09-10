#[cfg(test)]
mod tests;

use crate::application_authentication_service::ServerError::ProtocolError;
use crate::cryptography::Cryptography;
use crate::service_traits::{
    ApReplayCache, ApReplayEntry, PrincipalDatabase, ReplayCache, ReplayCacheEntry,
};
use chrono::{Local, SubsecRound};
use derive_builder::Builder;
use messages::basic_types::{
    EncryptedData, EncryptionKey, HostAddresses, Int32, KerberosTime, OctetString, PrincipalName,
    Realm, UInt32,
};
use messages::flags::TicketFlag;
use messages::{ApRep, ApReq, Authenticator, AuthenticatorBuilder, Ecode, EncTicketPart, Encode};
use messages::{Decode, KrbErrorMsg, KrbErrorMsgBuilder};
use std::cell::RefCell;
use std::time::Duration;

#[derive(Builder)]
#[builder(pattern = "owned", setter(strip_option))]
pub struct ApplicationAuthenticationService<'a, C, P>
where
    C: ApReplayCache,
    P: PrincipalDatabase,
{
    realm: Realm,
    sname: PrincipalName,
    principal_db: &'a P,
    accept_empty_address_ticket: bool,
    ticket_allowable_clock_skew: Duration,
    replay_cache: &'a C,
    crypto: Vec<Box<dyn Cryptography>>,
}

#[derive(Debug)]
enum ServerError {
    ProtocolError(KrbErrorMsg),
    Internal,
    CannotDecode,
}

impl<'a, C, K> ApplicationAuthenticationService<'a, C, K>
where
    C: ApReplayCache,
    K: PrincipalDatabase,
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

    fn get_key_for_decrypt(
        &self,
        sname: &PrincipalName,
        realm: &Realm,
        etype: Int32,
        knvo: Option<UInt32>,
    ) -> Result<EncryptionKey, Ecode> {
        // TODO: Check for key in session key cache first
        let principal_db = self.principal_db;
        let key = principal_db
            .get_principal(sname, realm)
            .ok_or(Ecode::KDC_ERR_S_PRINCIPAL_UNKNOWN)?;
        let key = key
            .key
            .keyvalue()
            .as_bytes();
        Ok(EncryptionKey::new(etype, OctetString::new(key).unwrap()))
    }

    pub fn handle_krb_ap_req(&self, ap_req: ApReq) -> Result<ApRep, ServerError> {
        let replay_cache = self.replay_cache;
        let crypto = &self.crypto;
        let mut error_msg = RefCell::new(self.default_error_builder());

        let mut build_protocol_error =
            |e| ProtocolError(error_msg.borrow_mut().error_code(e).build().unwrap());

        self.verify_msg_type(ap_req.msg_type())
            .and(self.verify_key(ap_req.ticket().tkt_vno()))
            .map_err(&mut build_protocol_error)?;

        let server = self
            .principal_db
            .get_principal(ap_req.ticket().sname(), ap_req.ticket().realm())
            .ok_or_else(|| build_protocol_error(Ecode::KRB_AP_ERR_BADKEYVER))?;

        let key = self
            .get_key_for_decrypt(
                ap_req.ticket().sname(),
                ap_req.ticket().realm(),
                *ap_req.ticket().enc_part().etype(),
                ap_req.ticket().enc_part().kvno().map(|v| *v),
            )
            .map_err(&mut build_protocol_error)?;

        let decrypted_ticket = crypto
            .iter()
            .find(|crypto| crypto.get_etype() == *key.keytype())
            .expect("This should be check when searching for key")
            .decrypt(
                ap_req.ticket().enc_part().cipher().as_bytes(),
                &key.keyvalue().as_bytes(),
            )
            .map_err(|_| ServerError::Internal)
            .and_then(|d| EncTicketPart::from_der(&d).map_err(|_| ServerError::Internal))?;

        let ss_key = decrypted_ticket.key().keyvalue().as_bytes();
        let authenticator = crypto
            .iter()
            .find(|crypto| crypto.get_etype() == *key.keytype())
            .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))?
            .decrypt(ap_req.authenticator().cipher().as_bytes(), &ss_key)
            .map_err(|_| ServerError::Internal)
            .and_then(|d| {
                Authenticator::from_der(&d)
                    .inspect_err(|e| println!("{:?}", e))
                    .map_err(|_| ServerError::Internal)
            })?;
        if authenticator.crealm() != ap_req.ticket().realm()
            || authenticator.cname() != ap_req.ticket().sname()
        {
            return Err(build_protocol_error(Ecode::KRB_AP_ERR_BADMATCH));
        }

        {
            error_msg
                .borrow_mut()
                .ctime(authenticator.ctime().to_owned())
                .cusec(authenticator.cusec().to_owned())
                .crealm(authenticator.crealm().to_owned())
                .cname(authenticator.cname().to_owned());
        }

        self.accept_empty_address_ticket
            .then_some(())
            .or(decrypted_ticket
                .caddr()
                .filter(|t| self.search_for_addresses(t))
                .and(Some(())))
            .ok_or(build_protocol_error(Ecode::KRB_AP_ERR_BADADDR))?;

        let ticket_time = decrypted_ticket
            .starttime()
            .unwrap_or(decrypted_ticket.authtime());

        if ticket_time - KerberosTime::now() > self.ticket_allowable_clock_skew
            || decrypted_ticket
                .flags()
                .is_set(TicketFlag::INVALID as usize)
        {
            return Err(build_protocol_error(Ecode::KRB_AP_ERR_TKT_NYV));
        }

        if KerberosTime::now() - decrypted_ticket.endtime() > self.ticket_allowable_clock_skew {
            return Err(build_protocol_error(Ecode::KRB_AP_ERR_TKT_EXPIRED));
        }

        replay_cache
            .store(&ApReplayEntry {
                ctime: authenticator.ctime().to_owned(),
                cusec: authenticator.cusec().to_owned(),
                cname: authenticator.cname().to_owned(),
                crealm: authenticator.crealm().to_owned(),
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
            .first()
            .expect("At least one crypto should be available")
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
