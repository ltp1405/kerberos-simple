use crate::cryptography::Cryptography;
use crate::service_traits::{
    PrincipalDatabase, PrincipalDatabaseRecord, ReplayCache, ReplayCacheEntry,
};
use chrono::{Local, SubsecRound};
use messages::basic_types::{
    AuthorizationData, Checksum, EncryptedData, EncryptionKey, Int32, KerberosTime, OctetString,
    PrincipalName, Realm,
};
use messages::flags::{KdcOptionsFlag, TicketFlag};
use messages::{
    ApReq, Authenticator, Decode, Ecode, EncKdcRepPartBuilder, EncTicketPart, Encode, KrbErrorMsg,
    KrbErrorMsgBuilder, LastReq, TgsRep, TgsReq, Ticket, TicketFlags,
};
use std::cell::Cell;
use std::cmp::min;
use std::ffi::c_long;

#[derive(Debug)]
pub enum ServerError {
    ProtocolError(KrbErrorMsg),
    Internal,
}

type TGSResult<T> = Result<T, ServerError>;

pub struct TicketGrantingService<'a, T, C>
where
    T: PrincipalDatabase,
    C: ReplayCache,
{
    supported_crypto: Vec<Box<dyn Cryptography>>,
    principal_db: &'a T,
    name: PrincipalName,
    realm: Realm,
    replay_cache: &'a C,
}

impl<'a, T: PrincipalDatabase, C: ReplayCache> TicketGrantingService<'a, T, C> {
    fn default_error_builder(&self) -> KrbErrorMsgBuilder {
        let now = Local::now();
        let time = now.round_subsecs(0).to_utc().timestamp();
        let usec = now.timestamp_subsec_micros();
        KrbErrorMsgBuilder::default()
            .stime(KerberosTime::now())
            .susec(usec as i32)
            .sname(self.name.clone())
            .realm(self.realm.clone())
            .to_owned()
    }

    fn is_tgt_local_realm(&self, ticket: &Ticket) -> bool {
        // TODO: Implement this
        true
    }

    fn verify_padata(&self, tgs_req: &TgsReq) -> Result<ApReq, Ecode> {
        let padata = tgs_req
            .padata()
            // 1 == pa-tgs-req
            .iter()
            .find_map(|padata| padata.iter().find(|padata| *padata.padata_type() == 1))
            .ok_or(Ecode::KDC_ERR_PADATA_TYPE_NOSUPP)?;
        let ap_req = ApReq::from_der(padata.padata_value().as_ref())
            .map_err(|_| Ecode::KDC_ERR_PADATA_TYPE_NOSUPP)?;
        Ok(ap_req)
    }

    fn get_tgt_realm(&self, enc_ticket_part: &EncTicketPart) -> Realm {
        enc_ticket_part.crealm().clone()
    }

    fn decrypt_authenticator(&self, ap_req: &ApReq) -> TGSResult<Authenticator> {
        todo!()
    }

    fn get_supported_checksums(&self) -> Vec<i32> {
        // TODO: Implement this
        vec![0]
    }

    fn compute_checksum(&self, data: &[u8], checksum_type: Int32) -> Vec<u8> {
        todo!()
    }

    fn generate_random_session_key(&self) -> Result<EncryptionKey, ServerError> {
        let crypto = self
            .supported_crypto
            .first()
            .expect("There should be at least one supported crypto");
        let key = crypto.generate_key().map_err(|_| ServerError::Internal)?;
        Ok(EncryptionKey::new(
            crypto.get_etype(),
            OctetString::new(key).unwrap(),
        ))
    }

    fn replay_detected(&self, ticket: &EncTicketPart) -> bool {
        // TODO: Implement request replay detection, https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3.1
        // This is a dummy implementation
        false
    }

    fn is_checksum_supported(&self, checksum: &Checksum) -> bool {
        // TODO: Implement this
        true
    }

    fn is_checksum_keyed(&self, checksum: &Checksum) -> bool {
        // TODO: Implement this
        true
    }

    fn is_checksum_collision_proof(&self, checksum: &Checksum) -> bool {
        // TODO: Implement this
        true
    }

    pub fn handle_tgs_req(&self, tgs_req: &TgsReq) -> TGSResult<TgsRep> {
        let find_crypto_for_etype = |etype: Int32| {
            self.supported_crypto
                .iter()
                .find(|crypto| crypto.get_etype() == etype)
        };

        let mut error = self.default_error_builder();

        /// Helper function to build a protocol error, supplied with an error code
        let mut build_protocol_error =
            |e: Ecode| ServerError::ProtocolError(error.error_code(e).build().unwrap());

        let ap_req = self
            .verify_padata(tgs_req)
            .map_err(&mut build_protocol_error)?;

        let server = self
            .principal_db
            .get_principal(
                tgs_req
                    .req_body()
                    .sname()
                    .expect("sname should be present in tgs_req"),
                tgs_req.req_body().realm(),
            )
            .ok_or(build_protocol_error(Ecode::KDC_ERR_S_PRINCIPAL_UNKNOWN))?;

        let client = self
            .principal_db
            .get_principal(ap_req.ticket().sname(), ap_req.ticket().realm())
            .ok_or(build_protocol_error(Ecode::KDC_ERR_C_PRINCIPAL_UNKNOWN))?;

        let kdc_options = tgs_req.req_body().kdc_options();
        let auth_header = ap_req;
        let tgt = auth_header.ticket();

        if !self.is_tgt_local_realm(tgt) && tgs_req.req_body().sname() != tgt.sname().into() {
            return Err(build_protocol_error(Ecode::KRB_AP_ERR_NOT_US));
        }

        let tgt = find_crypto_for_etype(*tgt.enc_part().etype())
            .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))?
            .decrypt(
                tgt.enc_part().cipher().as_bytes(),
                server.key.keyvalue().as_bytes(),
            )
            .map_err(|_| ServerError::Internal)
            .and_then(|data| {
                EncTicketPart::from_der(data.as_slice()).map_err(|_| ServerError::Internal)
            })?;

        let realm = self.get_tgt_realm(&tgt);

        let authenticator = find_crypto_for_etype(*server.key.keytype())
            .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))?
            .decrypt(
                auth_header.authenticator().cipher().as_bytes(),
                client.key.keyvalue().as_bytes(),
            )
            .map_err(|_| ServerError::Internal)
            .and_then(|data| {
                Authenticator::from_der(data.as_slice()).map_err(|_| ServerError::Internal)
            })?;

        authenticator
            .cksum()
            .ok_or(build_protocol_error(Ecode::KRB_AP_ERR_INAPP_CKSUM))
            .and_then(|t| {
                if !self.is_checksum_supported(&t) {
                    return Err(build_protocol_error(Ecode::KDC_ERR_SUMTYPE_NOSUPP));
                }
                Ok(t)
            })
            .and_then(|t| {
                if self.is_checksum_keyed(&t) && self.is_checksum_collision_proof(&t) {
                    return Err(build_protocol_error(Ecode::KDC_ERR_SUMTYPE_NOSUPP));
                }
                Ok(t)
            })
            .and_then(|c| {
                let checksum = self.compute_checksum(
                    tgs_req.req_body().to_der().unwrap().as_slice(),
                    *c.cksumtype(),
                );
                if checksum != c.checksum().as_bytes() {
                    return Err(build_protocol_error(Ecode::KRB_AP_ERR_MODIFIED));
                }
                Ok(c)
            })?;

        let session_key = self.generate_random_session_key()?;

        let use_etype = tgs_req
            .req_body()
            .etype()
            .iter()
            .find_map(|etype| find_crypto_for_etype(*etype))
            .map(|crypto| crypto.get_etype())
            .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))?;

        let mut tgt_rep = EncKdcRepPartBuilder::default();

        let mut new_ticket_enc_part = EncTicketPart::builder();
        if let Some(caddr) = tgt.caddr() {
            new_ticket_enc_part.caddr(caddr.clone());
        }

        let mut new_ticket_flags = TicketFlags::builder();

        /// Check if the flag is set in the tgs request, if not return a protocol error
        let mut check_tgs_req_flag = |flag: KdcOptionsFlag, err: Ecode| {
            if !tgs_req.req_body().kdc_options().is_set(flag as usize) {
                return Err(build_protocol_error(err));
            }
            Ok(())
        };

        if kdc_options.is_set(KdcOptionsFlag::FORWARDABLE as usize) {
            check_tgs_req_flag(KdcOptionsFlag::FORWARDABLE, Ecode::KDC_ERR_BADOPTION)?;
            new_ticket_flags.set(TicketFlag::FORWARDABLE as usize);
        }

        if kdc_options.is_set(KdcOptionsFlag::FORWARDED as usize) {
            check_tgs_req_flag(KdcOptionsFlag::FORWARDED, Ecode::KDC_ERR_BADOPTION)?;
            new_ticket_flags.set(TicketFlag::FORWARDED as usize);
            if let Some(caddr) = tgt.caddr() {
                new_ticket_enc_part.caddr(caddr.clone());
                tgt_rep.caddr(caddr.clone());
            }
        }

        if tgt.flags().is_set(TicketFlag::FORWARDED as usize) {
            new_ticket_flags.set(TicketFlag::FORWARDED as usize);
        }

        if kdc_options.is_set(KdcOptionsFlag::PROXIABLE as usize) {
            check_tgs_req_flag(KdcOptionsFlag::PROXIABLE, Ecode::KDC_ERR_BADOPTION)?;
            new_ticket_flags.set(TicketFlag::PROXIABLE as usize);
        }

        if kdc_options.is_set(KdcOptionsFlag::PROXY as usize) {
            check_tgs_req_flag(KdcOptionsFlag::PROXY, Ecode::KDC_ERR_BADOPTION)?;
            new_ticket_flags.set(TicketFlag::PROXY as usize);
            if let Some(caddr) = tgt.caddr() {
                new_ticket_enc_part.caddr(caddr.clone());
                tgt_rep.caddr(caddr.clone());
            }
        }

        // TODO: Check postdate flags

        if kdc_options.is_set(KdcOptionsFlag::VALIDATE as usize) {
            check_tgs_req_flag(KdcOptionsFlag::INVALID, Ecode::KDC_ERR_POLICY)?;
            if tgt.starttime().unwrap_or(KerberosTime::zero()) > KerberosTime::now() {
                return Err(build_protocol_error(Ecode::KRB_AP_ERR_TKT_NYV));
            }
            if self.replay_detected(&tgt) {
                return Err(build_protocol_error(Ecode::KRB_AP_ERR_REPEAT));
            }
            new_ticket_flags.set(TicketFlag::INVALID as usize);
        }

        // TODO: more flag verification

        new_ticket_enc_part.authtime(tgt.authtime().clone());

        let mut req_rtime = KerberosTime::zero();

        let kdc_time = KerberosTime::now();

        let mut req_renewable = false;

        if kdc_options.is_set(KdcOptionsFlag::RENEW as usize) {
            if !tgt.flags().is_set(TicketFlag::RENEWABLE as usize) {
                return Err(build_protocol_error(Ecode::KDC_ERR_BADOPTION));
            }
            if tgt.renew_till().unwrap_or(KerberosTime::zero()) >= kdc_time {
                return Err(build_protocol_error(Ecode::KRB_AP_ERR_TKT_EXPIRED));
            }
            new_ticket_enc_part.starttime(kdc_time);
            let old_life = tgt.endtime() - tgt.starttime().unwrap_or(tgt.authtime());
            new_ticket_enc_part.endtime(std::cmp::min(
                kdc_time + old_life,
                tgt.renew_till().unwrap_or(KerberosTime::max()),
            ));
            new_ticket_enc_part.starttime(kdc_time);
        } else {
            new_ticket_enc_part.starttime(kdc_time);
            let till = if tgs_req.req_body().till() == &KerberosTime::zero() {
                KerberosTime::max()
            } else {
                tgs_req.req_body().till().clone()
            };

            let new_tkt_endtime = [
                till,
                tgt.endtime(),
                // KerberosTime::now() + todo!("max life of client"),
                // KerberosTime::now() + todo!("max life of server"),
                // KerberosTime::now() + todo!("max life of realm"),
            ]
            .iter()
            .min()
            .unwrap()
            .clone();

            new_ticket_enc_part.endtime(new_tkt_endtime);

            if tgs_req
                .req_body()
                .kdc_options()
                .is_set(KdcOptionsFlag::RENEWABLE_OK as usize)
                && &new_tkt_endtime < tgs_req.req_body().till()
                && tgt.flags().is_set(TicketFlag::RENEWABLE as usize)
            {
                req_renewable = true;
                req_rtime = min(till, tgt.renew_till().unwrap_or(KerberosTime::max()));
            }
            req_rtime = min(till, tgt.renew_till().unwrap());
        }

        let rtime = if req_rtime == KerberosTime::zero() {
            KerberosTime::max()
        } else {
            req_rtime
        };

        if kdc_options.is_set(KdcOptionsFlag::RENEWABLE as usize) {
            new_ticket_flags.set(TicketFlag::RENEWABLE as usize);
            new_ticket_enc_part.renew_till(
                [
                    rtime,
                    // todo!("max renewable life of client"),
                    // todo!("max renewable life of server"),
                    // todo!("max renewable life of realm"),
                ]
                .iter()
                .min()
                .unwrap()
                .clone(),
            );
        }

        let decrypted_auth = tgs_req
            .req_body()
            .enc_authorization_data()
            .map(|auth_data| {
                let key = authenticator
                    .subkey()
                    .expect("enc_authorization_data must be decrypted with subkey");
                find_crypto_for_etype(*key.keytype())
                    .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))
                    .and_then(|crypto| {
                        crypto
                            .decrypt(auth_data.cipher().as_bytes(), key.keyvalue().as_bytes())
                            .map_err(|_| ServerError::Internal)
                            .map(|data| {
                                AuthorizationData::from_der(data.as_slice())
                                    .expect("authorization data should be decoded")
                            })
                    })
            });

        let auth_data = decrypted_auth.map(|decrypted_auth| {
            let auth_data = authenticator
                .authorization_data()
                .expect("authorization data should be present in authenticator")
                .iter()
                .map(|x| x.clone())
                .chain(decrypted_auth?.into_iter())
                .collect::<AuthorizationData>();
            Ok(auth_data)
        });
        if let Some(auth_data) = auth_data {
            new_ticket_enc_part.authorization_data(auth_data?);
        }

        new_ticket_enc_part.key(session_key.clone());
        new_ticket_enc_part.crealm(tgt.crealm().clone());
        new_ticket_enc_part.cname(authenticator.cname().clone());

        if self.get_tgt_realm(&tgt) == realm {
            new_ticket_enc_part.transited(tgt.transited().clone());
        } else {
            todo!("Inter-realm is currently not supported");
        }

        let ticket = new_ticket_enc_part.build().expect("ticket should be built");
        // Only encrypt case where server is specified
        let encrypted_ticket = self
            .supported_crypto
            .iter()
            .find(|crypto| crypto.get_etype() == *server.key.keytype())
            .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))?
            .encrypt(
                &ticket.to_der().expect("ticket should be encoded"),
                server.key.keyvalue().as_bytes(),
            )
            .map(|data| {
                EncryptedData::new(*server.key.keytype(), None, OctetString::new(data).unwrap())
            })
            .map_err(|_| ServerError::Internal)?;

        let new_ticket = Ticket::new(
            realm.clone(),
            tgs_req
                .req_body()
                .sname()
                .expect("sname should be present in tgs_req")
                .clone(),
            encrypted_ticket,
        );

        tgt_rep.key(session_key.clone());
        tgt_rep.last_req(self.fetch_last_request_info());
        tgt_rep.nonce(tgs_req.req_body().nonce().clone());
        tgt_rep.flags(new_ticket_flags.build().unwrap());
        tgt_rep.authtime(tgt.authtime().clone());
        if let Some(starttime) = tgt.starttime() {
            tgt_rep.starttime(starttime.clone());
        }
        tgt_rep.endtime(ticket.endtime().clone());

        if let Some(sname) = tgs_req.req_body().sname() {
            tgt_rep.sname(sname.clone());
        }
        tgt_rep.srealm(realm.clone());
        if ticket.flags().is_set(TicketFlag::RENEWABLE as usize) {
            if let Some(renew_till) = ticket.renew_till() {
                tgt_rep.renew_till(renew_till.clone());
            }
        }

        let tgt_rep = tgt_rep.build().expect("tgt_rep should be built");

        /// Encrypt data using `use_etype` encryption type
        let mut encrypt_data = |key: &[u8]| {
            self.supported_crypto
                .iter()
                .find(|crypto| crypto.get_etype() == use_etype)
                .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))?
                .encrypt(&tgt_rep.to_der().unwrap(), key)
                .map_err(|_| ServerError::Internal)
        };

        let tgs_rep = if let Some(subkey) = authenticator.subkey() {
            let data = encrypt_data(subkey.keyvalue().as_bytes())?;
            EncryptedData::new(
                *subkey.keytype(),
                None,
                OctetString::new(data).expect("data should be encrypted"),
            )
        } else {
            let data = encrypt_data(session_key.keyvalue().as_bytes())?;
            EncryptedData::new(
                *session_key.keytype(),
                None,
                OctetString::new(data).expect("data should be encrypted"),
            )
        };

        Ok(TgsRep::new(
            None,
            tgt.crealm().clone(),
            tgt.cname().clone(),
            new_ticket,
            tgs_rep,
        ))
    }

    fn fetch_last_request_info(&self) -> LastReq {
        todo!()
    }
}
