use crate::cryptography::Cryptography;
use crate::service_traits::PrincipalDatabaseRecord;
use crate::ticket_granting_service::ServerError::ProtocolError;
use chrono::{Local, SubsecRound};
use messages::basic_types::{
    AuthorizationData, EncryptedData, EncryptionKey, Int32, KerberosTime, OctetString,
    PrincipalName, Realm,
};
use messages::flags::{KdcOptionsFlag, TicketFlag};
use messages::{
    ApReq, Authenticator, Decode, Ecode, EncKdcRepPart, EncKdcRepPartBuilder, EncTgsRepPart,
    EncTicketPart, Encode, KrbErrorMsg, KrbErrorMsgBuilder, KrbErrorMsgBuilderError, LastReq,
    TgsRep, TgsReq, Ticket, TicketFlags,
};
use std::cmp::min;
use std::time::Duration;

#[derive(Debug)]
pub enum ServerError {
    ProtocolError(KrbErrorMsg),
    Internal,
}

type TGSResult<T> = Result<T, ServerError>;

pub struct TicketGrantingService {
    supported_crypto: Vec<Box<dyn Cryptography>>,
}

impl TicketGrantingService {
    fn default_error_builder(&self) -> KrbErrorMsgBuilder {
        let now = Local::now();
        let time = now.round_subsecs(0).to_utc().timestamp();
        let usec = now.timestamp_subsec_micros();
        KrbErrorMsgBuilder::default()
            .stime(KerberosTime::now())
            .susec(usec as i32)
            // .sname(self.sname.clone())
            // .realm(self.realm.clone())
            .to_owned()
    }

    fn is_tgt_local_realm(&self, ticket: &Ticket) -> bool {
        // ticket.srealm() == self.realm
        todo!()
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
        todo!()
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

    fn get_server(
        &self,
        principal_name: Option<&PrincipalName>,
        realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord> {
        todo!()
    }

    fn verify_authenticator(
        &self,
        authenticator: &Authenticator,
        tgs_req: &TgsReq,
    ) -> Result<(), Ecode> {
        authenticator
            .cksum()
            .ok_or(Ecode::KRB_AP_ERR_INAPP_CKSUM)
            .and_then(|cksum| {
                let supported_checksums = self.get_supported_checksums();
                if !supported_checksums.contains(&cksum.cksumtype()) {
                    return Err(Ecode::KRB_AP_ERR_INAPP_CKSUM);
                }
                if cksum.checksum().as_bytes()
                    != &self
                        .compute_checksum(&tgs_req.req_body().to_der().unwrap(), *cksum.cksumtype())
                {
                    return Err(Ecode::KRB_AP_ERR_MODIFIED);
                }
                Ok(())
            })
    }

    fn generate_random_session_key(&self) -> EncryptionKey {
        todo!()
    }

    fn get_supported_crypto<'a>(&self, etype: Int32) -> &[Box<&'a dyn Cryptography>] {
        todo!()
    }

    fn decrypt_ticket(&self, ticket: &Ticket) -> TGSResult<EncTicketPart> {
        todo!()
    }

    fn replay_detected(&self, ticket: &EncTicketPart) -> bool {
        todo!()
    }

    pub fn handle_tgs_req(&self, tgs_req: &TgsReq) -> TGSResult<TgsRep> {
        let mut error = self.default_error_builder();
        let ap_req = self
            .verify_padata(tgs_req)
            .map_err(|e| ServerError::ProtocolError(error.error_code(e).build().unwrap()))?;

        let auth_header = ap_req;
        let tgt = auth_header.ticket();

        if !self.is_tgt_local_realm(tgt) && tgs_req.req_body().sname() != tgt.sname().into() {
            return Err(ServerError::ProtocolError(
                error.error_code(Ecode::KRB_AP_ERR_NOT_US).build().unwrap(),
            ));
        }

        let tgt = self
            .decrypt_ticket(tgt)
            .map_err(|_| ServerError::Internal)?;

        let realm = self.get_tgt_realm(&tgt);

        let authenticator = self.decrypt_authenticator(&auth_header)?;

        if authenticator.cksum().is_none() {
            return Err(ServerError::ProtocolError(
                error
                    .error_code(Ecode::KRB_AP_ERR_INAPP_CKSUM)
                    .build()
                    .unwrap(),
            ));
        }

        let server = self.get_server(tgs_req.req_body().sname(), &realm).ok_or(
            // does not support outside realm, so we return a protocol error
            ServerError::ProtocolError(
                error
                    .error_code(Ecode::KDC_ERR_S_PRINCIPAL_UNKNOWN)
                    .build()
                    .unwrap(),
            ),
        )?;

        let session_key = self.generate_random_session_key();

        let use_etype = tgs_req
            .req_body()
            .etype()
            .iter()
            .find_map(|etype| {
                self.get_supported_crypto(*etype)
                    .iter()
                    .find(|crypto| crypto.get_etype() == *etype)
            })
            .map(|crypto| crypto.get_etype())
            .ok_or(ServerError::ProtocolError(
                error
                    .error_code(Ecode::KDC_ERR_ETYPE_NOSUPP)
                    .build()
                    .unwrap(),
            ))?;

        let mut tgt_rep = EncKdcRepPartBuilder::default();

        let mut new_ticket_enc_part = EncTicketPart::builder();
        let mut new_ticket_enc_part =
            new_ticket_enc_part.caddr(tgt.caddr().expect("caddr should be present in tgt").clone());

        let mut new_ticket_flags = TicketFlags::builder();

        let mut check_tgs_req_flag = |flag: KdcOptionsFlag, err: Ecode| {
            if !tgs_req.req_body().kdc_options().is_set(flag as usize) {
                return Err(ServerError::ProtocolError(
                    error.error_code(err).build().unwrap(),
                ));
            }
            Ok(())
        };

        if tgs_req
            .req_body()
            .kdc_options
            .is_set(KdcOptionsFlag::FORWARDABLE as usize)
        {
            check_tgs_req_flag(KdcOptionsFlag::FORWARDABLE, Ecode::KDC_ERR_BADOPTION)?;
            new_ticket_flags.set(TicketFlag::FORWARDABLE as usize);
        }

        if tgs_req
            .req_body()
            .kdc_options
            .is_set(KdcOptionsFlag::FORWARDED as usize)
        {
            check_tgs_req_flag(KdcOptionsFlag::FORWARDED, Ecode::KDC_ERR_BADOPTION)?;
            new_ticket_flags.set(TicketFlag::FORWARDED as usize);
            new_ticket_enc_part.caddr(
                tgs_req
                    .req_body()
                    .addresses()
                    .expect("addresses should be present in tgs_req")
                    .clone(),
            );
            tgt_rep.caddr(
                tgs_req
                    .req_body()
                    .addresses()
                    .expect("addresses should be present in tgs_req")
                    .clone(),
            );
        }

        if tgt.flags().is_set(TicketFlag::FORWARDED as usize) {
            new_ticket_flags.set(TicketFlag::FORWARDED as usize);
        }

        if tgs_req
            .req_body()
            .kdc_options()
            .is_set(KdcOptionsFlag::PROXIABLE as usize)
        {
            check_tgs_req_flag(KdcOptionsFlag::PROXIABLE, Ecode::KDC_ERR_BADOPTION)?;
            new_ticket_flags.set(TicketFlag::PROXIABLE as usize);
        }

        if tgs_req
            .req_body()
            .kdc_options()
            .is_set(KdcOptionsFlag::PROXY as usize)
        {
            check_tgs_req_flag(KdcOptionsFlag::PROXY, Ecode::KDC_ERR_BADOPTION)?;
            new_ticket_flags.set(TicketFlag::PROXY as usize);
            new_ticket_enc_part.caddr(
                tgs_req
                    .req_body()
                    .addresses()
                    .expect("addresses should be present in tgs_req")
                    .clone(),
            );
            tgt_rep.caddr(
                tgs_req
                    .req_body()
                    .addresses()
                    .expect("addresses should be present in tgs_req")
                    .clone(),
            );
        }

        // TODO: Check postdate flags

        if tgs_req
            .req_body()
            .kdc_options()
            .is_set(KdcOptionsFlag::VALIDATE as usize)
        {
            check_tgs_req_flag(KdcOptionsFlag::VALIDATE, Ecode::KDC_ERR_BADOPTION)?;
            if tgt.starttime().expect("starttime should be present in tgt") > KerberosTime::now() {
                return Err(ServerError::ProtocolError(
                    error.error_code(Ecode::KRB_AP_ERR_TKT_NYV).build().unwrap(),
                ));
            }
            if self.replay_detected(&tgt) {
                return Err(ServerError::ProtocolError(
                    error.error_code(Ecode::KRB_AP_ERR_REPEAT).build().unwrap(),
                ));
            }
            new_ticket_flags.set(TicketFlag::INVALID as usize);
        }

        // TODO: more flag verification

        new_ticket_enc_part.authtime(tgt.authtime().clone());

        let mut req_rtime = KerberosTime::from_unix_duration(Duration::from_secs(0)).unwrap();

        if tgs_req
            .req_body()
            .kdc_options()
            .is_set(KdcOptionsFlag::RENEW as usize)
        {
            if !tgt.flags().is_set(TicketFlag::RENEWABLE as usize) {
                return Err(ServerError::ProtocolError(
                    error.error_code(Ecode::KDC_ERR_BADOPTION).build().unwrap(),
                ));
            }
            if tgt
                .renew_till()
                .expect("renew_till should be present in tgt")
                >= KerberosTime::now()
            {
                return Err(ServerError::ProtocolError(
                    error
                        .error_code(Ecode::KRB_AP_ERR_TKT_EXPIRED)
                        .build()
                        .unwrap(),
                ));
            }
            new_ticket_enc_part.starttime(KerberosTime::now());
            let old_life = tgt.endtime() - tgt.starttime().unwrap();
            new_ticket_enc_part.endtime(std::cmp::min(
                KerberosTime::now() + old_life,
                tgt.renew_till()
                    .expect("renew_till should be present in tgt")
                    .clone(),
            ));
            new_ticket_enc_part.starttime(KerberosTime::now());
        } else {
            new_ticket_enc_part.starttime(KerberosTime::now());
            let till = if tgs_req.req_body().till().timestamp() == 0 {
                todo!("return infinite time")
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
            .expect("till and endtime should be present in tgs_req")
            .clone();

            new_ticket_enc_part.endtime(new_tkt_endtime);

            if tgs_req
                .req_body()
                .kdc_options()
                .is_set(KdcOptionsFlag::RENEWABLE_OK as usize)
                && new_tkt_endtime < till
                && tgt.flags().is_set(TicketFlag::RENEWABLE as usize)
            {
                new_ticket_flags.set(TicketFlag::RENEWABLE as usize);
                new_ticket_enc_part.renew_till(
                    tgt.renew_till()
                        .expect("renew_till should be present in tgt")
                        .clone(),
                );
            }
            req_rtime = min(till, tgt.renew_till().unwrap());
        }

        let rtime = if req_rtime.timestamp() == 0 {
            todo!("return infinite time")
        } else {
            tgs_req.req_body().rtime().unwrap()
        };

        if tgs_req
            .req_body()
            .kdc_options()
            .is_set(KdcOptionsFlag::RENEWABLE as usize)
        {
            new_ticket_flags.set(TicketFlag::RENEWABLE as usize);
            new_ticket_enc_part.renew_till(
                *[
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
                self.supported_crypto
                    .iter()
                    .find(|crypto| crypto.get_etype() == *key.keytype())
                    .ok_or(ServerError::ProtocolError(
                        error
                            .error_code(Ecode::KDC_ERR_ETYPE_NOSUPP)
                            .build()
                            .unwrap(),
                    ))
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
        let encrypted_ticket = self
            .supported_crypto
            .iter()
            .find(|crypto| crypto.get_etype() == *server.key.keytype())
            .ok_or(ServerError::ProtocolError(
                error
                    .error_code(Ecode::KDC_ERR_ETYPE_NOSUPP)
                    .build()
                    .unwrap(),
            ))?
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

        tgt_rep.sname(
            tgs_req
                .req_body()
                .sname()
                .expect("sname should be present in tgs_req")
                .clone(),
        );
        tgt_rep.srealm(realm.clone());
        if ticket.flags().is_set(TicketFlag::RENEWABLE as usize) {
            tgt_rep.renew_till(
                ticket
                    .renew_till()
                    .expect("renew_till should be present in ticket")
                    .clone(),
            );
        }

        let tgt_rep = tgt_rep.build().expect("tgt_rep should be built");

        /// Encrypt data using `use_etype` encryption type
        let mut encrypt_data = |key: &[u8]| {
            self.supported_crypto
                .iter()
                .find(|crypto| crypto.get_etype() == use_etype)
                .ok_or(ServerError::ProtocolError(
                    error
                        .error_code(Ecode::KDC_ERR_ETYPE_NOSUPP)
                        .build()
                        .unwrap(),
                ))?
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
