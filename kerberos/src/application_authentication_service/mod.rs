#[cfg(test)]
mod tests;

use crate::application_authentication_service::ServerError::ProtocolError;
use crate::cryptography::Cryptography;
use crate::service_traits::{ApReplayCache, ApReplayEntry, ClientAddressStorage, UserSessionEntry, UserSessionStorage};
use chrono::Local;
use derive_builder::Builder;
use messages::basic_types::{
    EncryptedData, EncryptionKey, HostAddresses, Int32, KerberosTime, OctetString, PrincipalName,
    Realm, UInt32,
};
use messages::flags::TicketFlag;
use messages::{ApRep, ApReq, Authenticator, AuthenticatorBuilder, Ecode, EncTicketPart, Encode};
use messages::{Decode, KrbErrorMsg, KrbErrorMsgBuilder};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Builder)]
#[builder(pattern = "owned", setter(strip_option))]
pub struct ApplicationAuthenticationService<'a, C, S>
where
    C: ApReplayCache,
    S: UserSessionStorage,
{
    realm: Realm,
    sname: PrincipalName,
    service_key: EncryptionKey,
    accept_empty_address_ticket: bool,
    ticket_allowable_clock_skew: Duration,
    address_storage: &'a dyn ClientAddressStorage,
    replay_cache: &'a C,
    crypto: Vec<Box<dyn Cryptography + Send + Sync>>,
    session_storage: &'a S,
}

#[derive(Debug)]
pub enum ServerError {
    ProtocolError(Box<KrbErrorMsg>),
    Internal,
}

impl<'a, C, S> ApplicationAuthenticationService<'a, C, S>
where
    C: ApReplayCache,
    S: UserSessionStorage,
{
    fn verify_msg_type(&self, msg_type: &u8) -> Result<(), Ecode> {
        match msg_type {
            14 => Ok(()),
            _ => Err(Ecode::KRB_AP_ERR_MSG_TYPE),
        }
    }
    fn verify_key(&self, _key_version: &Int32) -> Result<(), Ecode> {
        // TODO: correctly implement this
        Ok(())
    }

    async fn search_for_addresses(&self, ap_req: &ApReq, host_addresses: &HostAddresses) -> bool {
        let sender = self.address_storage.get_sender_of_packet(ap_req).await;
        host_addresses.iter().any(|a| a == &sender)
    }

    fn default_error_builder(&self) -> KrbErrorMsgBuilder {
        let now = Local::now();
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
        let key = self.service_key.keyvalue().as_bytes();
        Ok(EncryptionKey::new(etype, OctetString::new(key).unwrap()))
    }

    pub async fn handle_krb_ap_req(&self, ap_req: ApReq) -> Result<ApRep, ServerError> {
        let replay_cache = self.replay_cache;
        let crypto = &self.crypto;
        let mut error_msg = Mutex::new(self.default_error_builder());

        let build_protocol_error = |e| {
            ProtocolError(Box::new(
                error_msg.lock().unwrap().error_code(e).build().unwrap(),
            ))
        };

        self.verify_msg_type(ap_req.msg_type())
            .and(self.verify_key(ap_req.ticket().tkt_vno()))
            .map_err(build_protocol_error)?;

        let key = self
            .get_key_for_decrypt(
                ap_req.ticket().sname(),
                ap_req.ticket().realm(),
                *ap_req.ticket().enc_part().etype(),
                ap_req.ticket().enc_part().kvno().copied(),
            )
            .map_err(build_protocol_error)?;

        let decrypted_ticket = crypto
            .iter()
            .find(|crypto| crypto.get_etype() == *key.keytype())
            .expect("This should be check when searching for key")
            .decrypt(
                ap_req.ticket().enc_part().cipher().as_bytes(),
                key.keyvalue().as_bytes(),
            )
            .map_err(|_| ServerError::Internal)
            .and_then(|d| {
                EncTicketPart::from_der(&d)
                    .map_err(|_| build_protocol_error(Ecode::KRB_AP_ERR_BAD_INTEGRITY))
            })?;

        let ss_key = decrypted_ticket.key();
        let authenticator = crypto
            .iter()
            .find(|crypto| crypto.get_etype() == *ss_key.keytype())
            .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))?
            .decrypt(
                ap_req.authenticator().cipher().as_bytes(),
                ss_key.keyvalue().as_bytes(),
            )
            .map_err(|_| ServerError::Internal)
            .and_then(|d| {
                Authenticator::from_der(&d)
                    .inspect_err(|e| println!("ENC {:?}", e))
                    .map_err(|_| build_protocol_error(Ecode::KRB_AP_ERR_BAD_INTEGRITY))
            })?;
        if authenticator.crealm() != decrypted_ticket.crealm()
            || authenticator.cname() != decrypted_ticket.cname()
        {
            return Err(build_protocol_error(Ecode::KRB_AP_ERR_BADMATCH));
        }

        if authenticator.ctime().abs_diff(&KerberosTime::now()) > self.ticket_allowable_clock_skew {
            return Err(build_protocol_error(Ecode::KRB_AP_ERR_SKEW));
        }

        {
            error_msg
                .lock()
                .unwrap()
                .ctime(authenticator.ctime().to_owned())
                .cusec(authenticator.cusec().to_owned())
                .crealm(authenticator.crealm().to_owned())
                .cname(authenticator.cname().to_owned());
        }

        if self
            .replay_cache
            .contain(&ApReplayEntry {
                ctime: authenticator.ctime().to_owned(),
                cusec: authenticator.cusec().to_owned(),
                cname: authenticator.cname().to_owned(),
                crealm: authenticator.crealm().to_owned(),
            })
            .await
            .map_err(|_| ServerError::Internal)?
        {
            return Err(build_protocol_error(Ecode::KRB_AP_ERR_REPEAT));
        }

        if !self.accept_empty_address_ticket {
            if let Some(addr) = decrypted_ticket.caddr() {
                if !self.search_for_addresses(&ap_req, addr).await {
                    return Err(build_protocol_error(Ecode::KRB_AP_ERR_BADADDR));
                }
            }
        }

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

        if decrypted_ticket
            .endtime()
            .checked_sub_kerberos_time(KerberosTime::now())
            .filter(|t| t > &self.ticket_allowable_clock_skew)
            .is_none()
        {
            return Err(build_protocol_error(Ecode::KRB_AP_ERR_TKT_EXPIRED));
        }

        replay_cache
            .store(&ApReplayEntry {
                ctime: authenticator.ctime().to_owned(),
                cusec: authenticator.cusec().to_owned(),
                cname: authenticator.cname().to_owned(),
                crealm: authenticator.crealm().to_owned(),
            })
            .await
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

        self.session_storage
            .store_session(&UserSessionEntry {
                cname: authenticator.cname().to_owned(),
                crealm: authenticator.crealm().to_owned(),
                session_key: decrypted_ticket.key().to_owned(),
            })
            .await
            .map_err(|_| ServerError::Internal)?;

        Ok(ApRep::new(EncryptedData::new(
            *ap_req.ticket().enc_part().etype(),
            ap_req.ticket().enc_part().kvno().copied(),
            OctetString::new(encrypted)
                .map_err(|_| build_protocol_error(Ecode::KRB_AP_ERR_MODIFIED))?,
        )))
    }
}
