use crate::authentication_service::ServerError::ProtocolError;
use crate::cryptography::Cryptography;
use chrono::{Local, SubsecRound};
use derive_builder::Builder;
use messages::basic_types::{
    AddressTypes, EncryptedData, EncryptionKey, HostAddress, HostAddresses, Int32, KerberosTime,
    NameTypes, OctetString, PrincipalName, Realm, SequenceOf,
};
use messages::flags::{KdcOptionsFlag, TicketFlag};
use messages::{
    AsRep, AsReq, Ecode, EncKdcRepPartBuilder, EncTicketPart, Encode, KrbErrorMsg,
    KrbErrorMsgBuilder, LastReq, LastReqEntry, Ticket, TicketFlags, TransitedEncoding,
};
use std::ops::{Range, RangeBounds, RangeInclusive};
use std::thread::available_parallelism;
use std::time::{Duration, SystemTime};
use crate::service_traits::{PrincipalDatabase, PrincipalDatabaseRecord};

#[cfg(test)]
mod tests;
mod traits;

#[derive(Debug)]
enum ServerError {
    ProtocolError(KrbErrorMsg),
    Internal,
    CannotDecode,
}

#[derive(Builder)]
#[builder(pattern = "owned", setter(strip_option))]
struct AuthenticationService<'a, P>
where
    P: PrincipalDatabase
{
    require_pre_authenticate: bool,
    supported_crypto_systems: Vec<Box<dyn Cryptography>>,
    principal_db: &'a P,
    realm: Realm,
    sname: PrincipalName,
}

type Result<T> = std::result::Result<T, ServerError>;

impl<'a, P> AuthenticationService<'a, P>
where
    P: PrincipalDatabase,
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

    fn generate_suitable_session_key(
        &self,
        etypes: &SequenceOf<Int32>,
    ) -> Option<Result<EncryptionKey>> {
        etypes.iter().find_map(|etype| {
            self.get_supported_crypto_systems()
                .iter()
                .find_map(|crypto| {
                    if crypto.get_etype() == *etype {
                        Some(
                            crypto
                                .generate_key()
                                .map_err(|_| ServerError::Internal)
                                .map(|key| {
                                    EncryptionKey::new(
                                        etype.clone(),
                                        OctetString::new(key).unwrap(),
                                    )
                                }),
                        )
                    } else {
                        None
                    }
                })
        })
    }

    fn get_supported_crypto_systems(&self) -> &[Box<dyn Cryptography>] {
        self.supported_crypto_systems.as_slice()
    }

    fn get_endtime(&self, as_req: &AsReq) -> KerberosTime {
        // TODO: implement this correctly
        let till = as_req.req_body().till();
        if till.to_unix_duration() == Duration::from_secs(0) {
            todo!("Max this out")
        } else {
            *till
        }
    }

    fn get_client(&self, as_req: &AsReq) -> Option<PrincipalDatabaseRecord> {
        as_req
            .req_body()
            .cname()
            .and_then(|cname| self.principal_db.get_principal(&cname, &self.realm))
    }

    fn get_server(&self, as_req: &AsReq) -> Option<PrincipalDatabaseRecord> {
        as_req
            .req_body()
            .sname()
            .and_then(|sname| self.principal_db.get_principal(&sname, &self.realm))
    }

    fn handle_krb_as_req(&self, client_addr: HostAddress, as_req: &AsReq) -> Result<AsRep> {
        let mut error_msg = self.default_error_builder();
        let kdc_time = KerberosTime::now();
        let client = self.get_client(as_req).ok_or(ProtocolError(
            error_msg
                .error_code(Ecode::KDC_ERR_C_PRINCIPAL_UNKNOWN)
                .build()
                .unwrap(),
        ))?;
        let server = self.get_server(as_req).ok_or(ProtocolError(
            error_msg
                .error_code(Ecode::KDC_ERR_S_PRINCIPAL_UNKNOWN)
                .build()
                .unwrap(),
        ))?;
        let client_key = client.key;
        let server_key = server.key;

        if self.require_pre_authenticate {
            if as_req.padata().is_none() {
                return Err(ProtocolError(
                    error_msg
                        .error_code(Ecode::KDC_ERR_PREAUTH_REQUIRED)
                        .build()
                        .unwrap(),
                ));
            }
            todo!("Pre-auth is not yet implemented")
        }
        self.verify_encryption_type(as_req)?;

        let use_crypto_system = self
            .get_supported_crypto_systems()
            .iter()
            .find_map(|crypto| {
                as_req.req_body().etype().iter().find_map(|etype| {
                    if crypto.get_etype() == *etype {
                        Some(crypto)
                    } else {
                        None
                    }
                })
            })
            .ok_or(ProtocolError(
                error_msg
                    .error_code(Ecode::KDC_ERR_ETYPE_NOSUPP)
                    .build()
                    .unwrap(),
            ))?;

        let session_key = self
            .generate_suitable_session_key(as_req.req_body().etype())
            .ok_or(ProtocolError(
                error_msg
                    .error_code(Ecode::KDC_ERR_ETYPE_NOSUPP)
                    .build()
                    .unwrap(),
            ))??;

        let selected_client_key = client_key;

        let starttime = self
            .get_starttime(as_req)
            .map_err(|e| ProtocolError(error_msg.error_code(e).build().unwrap()))?;

        let ticket_expire_time = self.calculate_ticket_expire_time(as_req.req_body().till());

        let renew_till = self
            .calculate_renew_till(as_req)
            .map_err(|e| ProtocolError(error_msg.error_code(e).build().unwrap()))?;

        let ticket_flags = self.generate_ticket_flags(as_req).unwrap();

        let mut ticket = EncTicketPart::builder();
        if let Some(v) = renew_till {
            ticket.renew_till(v);
        }
        if let Some(addr) = as_req.req_body().addresses() {
            ticket.caddr(addr.clone());
        }
        let session_key = EncryptionKey::new(
            0,
            OctetString::new(session_key.keyvalue().as_bytes()).unwrap(),
        );

        let endtime = self.get_endtime(as_req);
        let ticket = ticket
            .flags(ticket_flags.clone())
            .starttime(starttime)
            .cname(
                as_req
                    .req_body()
                    .cname()
                    .ok_or_else(|| todo!("What should be here???"))?
                    .clone(),
            )
            .crealm(as_req.req_body().realm().clone())
            .key(session_key.clone())
            .transited(TransitedEncoding::empty(0))
            .authtime(kdc_time)
            .endtime(endtime)
            .build()
            .unwrap();

        let enc_ticket = self
            .get_supported_crypto_systems()
            .iter()
            .filter(|crypto| crypto.get_etype() == *server_key.keytype())
            .next()
            .unwrap()
            .encrypt(&ticket.to_der().unwrap(), server_key.keyvalue().as_bytes())
            .unwrap();

        let sname = as_req.req_body().sname().unwrap().clone();
        let srealm = as_req.req_body().realm().clone();

        let ticket = Ticket::new(
            srealm.clone(),
            sname.clone(),
            EncryptedData::new(0, 0, OctetString::new(enc_ticket).unwrap()),
        );

        let mut enc_part = EncKdcRepPartBuilder::default();
        if let Some(v) = renew_till {
            enc_part.renew_till(v);
        }
        let enc_part = enc_part
            .sname(sname)
            .srealm(srealm)
            .key(session_key)
            .last_req(vec![])
            .flags(ticket_flags)
            .starttime(starttime)
            .endtime(endtime)
            .authtime(kdc_time)
            .caddr(HostAddresses::from([client_addr]))
            .nonce(*as_req.req_body().nonce())
            .build()
            .unwrap();

        let enc_part = use_crypto_system
            .encrypt(
                &enc_part.to_der().unwrap(),
                selected_client_key.keyvalue().as_bytes(),
            )
            .map_err(|_| ServerError::Internal)
            .map(|x| {
                EncryptedData::new(
                    *selected_client_key.keytype(),
                    client.p_kvno,
                    OctetString::new(x).unwrap(),
                )
            })?;

        Ok(AsRep::new(
            None, // pre-auth is not implemented
            as_req.req_body().realm().clone(),
            as_req.req_body().cname().unwrap().clone(),
            ticket,
            enc_part,
        ))
    }

    fn verify_encryption_type(&self, as_req: &AsReq) -> Result<()> {
        Ok(())
    }

    // TODO: implement this correctly
    fn generate_ticket_flags(&self, as_req: &AsReq) -> std::result::Result<TicketFlags, Ecode> {
        let kdc_options = as_req.req_body().kdc_options();
        let mut ticket_flag = TicketFlags::builder();
        if kdc_options.is_set(KdcOptionsFlag::FORWARDABLE as usize) {
            ticket_flag.set(TicketFlag::FORWARDABLE as usize);
        }

        if kdc_options.is_set(KdcOptionsFlag::FORWARDED as usize) {
            ticket_flag.set(TicketFlag::FORWARDED as usize);
        }

        if kdc_options.is_set(KdcOptionsFlag::PROXIABLE as usize) {
            ticket_flag.set(TicketFlag::PROXIABLE as usize);
        }

        if kdc_options.is_set(KdcOptionsFlag::ALLOW_POSTDATE as usize) {
            ticket_flag.set(TicketFlag::PROXY as usize);
        }

        Ok(ticket_flag.build().unwrap())
    }

    // TODO: implement this correctly
    fn calculate_renew_till(
        &self,
        as_req: &AsReq,
    ) -> std::result::Result<Option<KerberosTime>, Ecode> {
        if as_req
            .req_body()
            .kdc_options()
            .is_set(messages::flags::KdcOptionsFlag::RENEWABLE as usize)
        {
            Ok(Some(
                KerberosTime::now() + Duration::from_secs(60 * 60 * 24),
            ))
        } else {
            Ok(None)
        }
    }

    fn verify_kdc_option(&self, as_req: AsReq) -> std::result::Result<(), Ecode> {
        let kdc_options = as_req.req_body().kdc_options();
        if kdc_options.is_set(KdcOptionsFlag::RENEW as usize)
            || kdc_options.is_set(KdcOptionsFlag::VALIDATE as usize)
            || kdc_options.is_set(KdcOptionsFlag::ENC_TKT_IN_SKEY as usize)
            || kdc_options.is_set(KdcOptionsFlag::FORWARDED as usize)
            || kdc_options.is_set(KdcOptionsFlag::PROXY as usize)
        {
            Err(Ecode::KDC_ERR_BADOPTION)
        } else {
            Ok(())
        }
    }

    fn calculate_ticket_expire_time(&self, requested_endtime: &KerberosTime) -> KerberosTime {
        Some(requested_endtime)
            .filter(|x| x.to_unix_duration() == Duration::from_secs(0))
            .map(|x| *x)
            .unwrap_or(self.get_maximum_endtime_allowed())
    }

    // TODO: implement this correctly
    fn get_maximum_endtime_allowed(&self) -> KerberosTime {
        KerberosTime::now() + Duration::from_secs(60 * 60 * 24)
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
            .kdc_options()
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
}
