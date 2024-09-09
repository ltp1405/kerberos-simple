use crate::cryptography::Cryptography;
use crate::service_traits::PrincipalDatabaseRecord;
use chrono::{Duration, Local, SubsecRound};
use messages::basic_types::{EncryptionKey, Int32, KerberosTime, PrincipalName, Realm};
use messages::flags::{KdcOptionsFlag, TicketFlag};
use messages::{
    ApReq, Authenticator, Decode, Ecode, EncKdcRepPart, EncKdcRepPartBuilder, EncTgsRepPart,
    EncTicketPart, Encode, KrbErrorMsg, KrbErrorMsgBuilder, KrbErrorMsgBuilderError, TgsRep,
    TgsReq, Ticket, TicketFlags,
};

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

    fn generate_random_session_key(&self) -> Vec<u8> {
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

        let new_ticket_enc_part = EncTicketPart::builder()
            .caddr(tgt.caddr().expect("caddr should be present in tgt").clone());

        let mut new_ticket_flags = TicketFlags::builder();

        if tgs_req
            .req_body()
            .kdc_options
            .is_set(KdcOptionsFlag::FORWARDABLE as usize)
        {
            if !tgt.flags().is_set(TicketFlag::FORWARDABLE as usize) {
                return Err(ServerError::ProtocolError(
                    error.error_code(Ecode::KDC_ERR_BADOPTION).build().unwrap(),
                ));
            }
            new_ticket_flags.set(TicketFlag::FORWARDABLE as usize);
        }

        if tgs_req
            .req_body()
            .kdc_options
            .is_set(KdcOptionsFlag::FORWARDED as usize)
        {
            if !tgt.flags().is_set(TicketFlag::FORWARDABLE as usize) {
                return Err(ServerError::ProtocolError(
                    error.error_code(Ecode::KDC_ERR_BADOPTION).build().unwrap(),
                ));
            }
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
            if !tgt.flags().is_set(TicketFlag::PROXIABLE as usize) {
                return Err(ServerError::ProtocolError(
                    error.error_code(Ecode::KDC_ERR_BADOPTION).build().unwrap(),
                ));
            }
            new_ticket_flags.set(TicketFlag::PROXIABLE as usize);
        }

        if tgs_req
            .req_body()
            .kdc_options()
            .is_set(KdcOptionsFlag::PROXY as usize)
        {
            if !tgt.flags().is_set(TicketFlag::PROXIABLE as usize) {
                return Err(ServerError::ProtocolError(
                    error.error_code(Ecode::KDC_ERR_BADOPTION).build().unwrap(),
                ));
            }
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
            if !tgt.flags().is_set(TicketFlag::INVALID as usize) {
                return Err(ServerError::ProtocolError(
                    error.error_code(Ecode::KDC_ERR_POLICY).build().unwrap(),
                ));
            }
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
            let old_life = tgt.endtime() - tgt.starttime();
            new_ticket_enc_part.endtime(std::cmp::min(
                KerberosTime::now() + old_life,
                tgt.renew_till()
                    .expect("renew_till should be present in tgt")
                    .clone(),
            ));
        } else {
        }

        todo!()
    }
}
