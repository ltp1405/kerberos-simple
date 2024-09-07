use crate::authentication_service::ServerError::ProtocolError;
use crate::cryptography::Cryptography;
use chrono::{Local, SubsecRound};
use messages::basic_types::{
    AddressTypes, EncryptedData, EncryptionKey, HostAddress, HostAddresses, Int32, KerberosTime,
    NameTypes, OctetString, PrincipalName, Realm, SequenceOf,
};
use messages::{
    AsRep, AsReq, Ecode, EncKdcRepPartBuilder, EncTicketPart, Encode, KrbErrorMsg,
    KrbErrorMsgBuilder, LastReq, LastReqEntry, Ticket, TicketFlags,
};
use std::ops::{Range, RangeBounds, RangeInclusive};
use std::thread::available_parallelism;
use std::time::Duration;

#[cfg(test)]
mod tests;

pub trait PrincipalDatabase {
    fn get_client_principal_key(&self, principal_name: &PrincipalName) -> Option<Vec<u8>>;
    fn get_server_principal_key(&self, principal_name: &PrincipalName) -> Option<Vec<u8>>;
}
#[derive(Debug)]
enum ServerError {
    ProtocolError(KrbErrorMsg),
    Internal,
    CannotDecode,
}

struct AuthenticationService<'a, P, C>
where
    P: PrincipalDatabase,
    C: Cryptography,
{
    require_pre_authenticate: bool,
    principal_db: &'a P,
    crypto: &'a C,
    realm: Realm,
    sname: PrincipalName,
}

type Result<T> = std::result::Result<T, ServerError>;

impl<'a, P, C> AuthenticationService<'a, P, C>
where
    P: PrincipalDatabase,
    C: Cryptography,
{
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

    fn handle_krb_as_req(&self, client_addr: HostAddress, as_req: &AsReq) -> Result<AsRep> {
        let mut error_msg = self.default_error_builder();
        self.principal_db.get_client_principal_key(
            as_req.req_body().cname().ok_or(ServerError::ProtocolError(
                error_msg
                    .error_code(Ecode::KDC_ERR_C_PRINCIPAL_UNKNOWN)
                    .build()
                    .unwrap(),
            ))?,
        );

        let server_key = self.principal_db.get_server_principal_key(
            as_req.req_body().cname().ok_or(ServerError::ProtocolError(
                error_msg
                    .error_code(Ecode::KDC_ERR_S_PRINCIPAL_UNKNOWN)
                    .build()
                    .unwrap(),
            ))?,
        );

        if self.require_pre_authenticate {
            todo!("Pre-auth is not yet implemented")
        }
        self.verify_encryption_type(as_req)?;

        let ss_key = self
            .crypto
            .generate_key()
            .map_err(|_| ServerError::Internal)?;

        let selected_client_key = self.get_suitable_encryption_key(as_req.req_body().etype())?;

        let starttime = self
            .get_starttime(as_req)
            .map_err(|e| ProtocolError(error_msg.error_code(e).build().unwrap()))?;

        let ticket_expire_time = self
            .calculate_ticket_expire_time(as_req.req_body().till())
            .map_err(|e| ProtocolError(error_msg.error_code(e).build().unwrap()))?;

        let renew_till = self
            .calculate_renew_till(as_req)
            .map_err(|e| ProtocolError(error_msg.error_code(e).build().unwrap()))?;

        let ticket_flags = self.generate_ticket_flags(as_req).unwrap();

        let ticket = EncTicketPart::builder()
            .flags(ticket_flags.clone())
            .renew_till(renew_till)
            .starttime(starttime)
            .cname(
                as_req
                    .req_body()
                    .cname()
                    .ok_or_else(|| todo!("What should be here???"))?
                    .clone(),
            )
            .crealm(as_req.req_body().realm().clone())
            // TODO: what should be the key type?
            .key(EncryptionKey::new(
                0,
                OctetString::new(ss_key.clone()).unwrap(),
            ))
            .build()
            .unwrap()
            .to_der()
            .unwrap();

        let enc_key = self.get_enc_key().ok_or(ServerError::Internal)?;
        let enc_ticket = self.crypto.encrypt(&ticket, &enc_key).unwrap();
        let ticket = Ticket::new(
            self.realm.clone(),
            self.sname.clone(),
            EncryptedData::new(0, 0, OctetString::new(enc_ticket).unwrap()),
        );

        let enc_part = EncKdcRepPartBuilder::default()
            .key(EncryptionKey::new(0, OctetString::new(ss_key).unwrap()))
            .last_req(vec![])
            .flags(ticket_flags)
            .renew_till(renew_till)
            .starttime(starttime)
            .caddr(HostAddresses::from([client_addr]))
            .nonce(*as_req.req_body().nonce())
            .build()
            .unwrap();

        let enc_part = EncryptedData::new(0, 0u32, OctetString::new([1, 2, 3]).unwrap());

        Ok(AsRep::new(
            None, // pre-auth is not implemented
            as_req.req_body().realm.clone(),
            PrincipalName::new(
                NameTypes::NtPrincipal, // TODO: is this correct???
                vec![],
            )
            .unwrap(),
            ticket,
            enc_part,
        ))
    }

    fn get_enc_key(&self) -> Option<Vec<u8>> {
        todo!()
    }

    fn verify_encryption_type(&self, as_req: &AsReq) -> Result<()> {
        Ok(())
    }

    fn generate_ticket_flags(&self, as_req: &AsReq) -> std::result::Result<TicketFlags, Ecode> {
        todo!()
    }

    fn calculate_renew_till(&self, as_req: &AsReq) -> std::result::Result<KerberosTime, Ecode> {
        todo!()
    }

    fn calculate_ticket_expire_time(
        &self,
        as_req: &KerberosTime,
    ) -> std::result::Result<KerberosTime, Ecode> {
        todo!()
        // Some(as_req.req_body().till())
        //     .and_then(|x| if x.to_unix_duration() == Duration::from_secs(0) {
        //         Some(x) } else {None
        //     }
        //     ).unwrap_or(
        //     self.get_maximum_endtime_allowed()
        // )
        // if as_req.req_body().till().to_unix_duration() == Duration::from_secs(0) {
        //     self.get_maximum_endtime_allowed()
        // }
        // as_req.req_body().till()
    }

    fn get_acceptable_clock_skew(&self) -> RangeInclusive<KerberosTime> {
        let now = KerberosTime::now();
        // TODO: correctly implement this
        (now - Duration::from_secs(60 * 5))..=(now + Duration::from_secs(60 * 5))
    }

    fn get_starttime(&self, as_req: &AsReq) -> std::result::Result<KerberosTime, Ecode> {
        let now = KerberosTime::now();
        let acceptable_clock_skew = self.get_acceptable_clock_skew();
        let postdated = as_req
            .req_body()
            .kdc_options
            .is_set(messages::flags::KdcOptionsFlag::POSTDATED as usize);
        let start_time = as_req.req_body().from();
        if start_time.is_none()
            || start_time
                .is_some_and(|t| (t < &now || acceptable_clock_skew.contains(t)) && !postdated)
        {
            Ok(now)
        } else if !postdated
            && start_time.is_some_and(|t| t > &now && !acceptable_clock_skew.contains(t))
        {
            Err(Ecode::KDC_ERR_CANNOT_POSTDATE)
        } else {
            todo!("This section should be checked using local policy")
        }
    }

    fn get_suitable_encryption_key(&self, etype: &SequenceOf<Int32>) -> Result<Vec<u8>> {
        todo!()
    }
}
