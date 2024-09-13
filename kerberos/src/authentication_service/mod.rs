use crate::authentication_service::ServerError::ProtocolError;
use crate::cryptography::Cryptography;
use crate::service_traits::{PrincipalDatabase, PrincipalDatabaseRecord};
use chrono::{Local, SubsecRound};
use derive_builder::Builder;
use messages::basic_types::{
    EncryptedData, EncryptionKey, Int32, KerberosFlagsBuilder, KerberosTime, OctetString,
    PrincipalName, Realm, SequenceOf,
};
use messages::flags::{KdcOptionsFlag, TicketFlag};
use messages::{
    AsRep, AsReq, Ecode, EncAsRepPart, EncKdcRepPartBuilder, EncTicketPart, Encode, KrbErrorMsg,
    KrbErrorMsgBuilder, Ticket, TicketFlags, TransitedEncoding,
};
use std::ops::RangeInclusive;
use std::time::Duration;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum ServerError {
    ProtocolError(Box<KrbErrorMsg>),
    Internal,
    CannotDecode,
}

#[derive(Builder)]
#[builder(pattern = "owned", setter(strip_option))]
pub struct AuthenticationService<'a, P>
where
    P: PrincipalDatabase,
{
    require_pre_authenticate: bool,
    supported_crypto_systems: Vec<Box<dyn Cryptography>>,
    principal_db: &'a P,
    realm: Realm,
    sname: PrincipalName,
}

pub type Result<T> = std::result::Result<T, ServerError>;

impl<'a, P> AuthenticationService<'a, P>
where
    P: PrincipalDatabase,
{
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

    async fn get_client(&self, as_req: &AsReq) -> Option<PrincipalDatabaseRecord> {
        if let Some(cname) = as_req.req_body().cname() {
            Some(self.principal_db.get_principal(cname, &self.realm).await?)
        } else {
            None
        }
    }

    async fn get_server(&self, as_req: &AsReq) -> Option<PrincipalDatabaseRecord> {
        if let Some(sname) = as_req.req_body().sname() {
            Some(self.principal_db.get_principal(sname, &self.realm).await?)
        } else {
            None
        }
    }

    pub async fn handle_krb_as_req(&self, as_req: &AsReq) -> Result<AsRep> {
        let mut error_msg = self.default_error_builder();
        // Helper function to build a protocol error, supplied with an error code
        let mut build_protocol_error =
            |e: Ecode| ProtocolError(Box::new(error_msg.error_code(e).build().unwrap()));
        let kdc_time = KerberosTime::now();
        let client = self
            .get_client(as_req)
            .await
            .ok_or(build_protocol_error(Ecode::KDC_ERR_C_PRINCIPAL_UNKNOWN))?;
        let server = self
            .get_server(as_req)
            .await
            .ok_or(build_protocol_error(Ecode::KDC_ERR_S_PRINCIPAL_UNKNOWN))?;
        let client_key = client.key;
        let server_key = server.key;

        if self.require_pre_authenticate {
            if as_req.padata().is_none() {
                return Err(build_protocol_error(Ecode::KDC_ERR_PREAUTH_REQUIRED));
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
            .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))?;

        let session_key = self
            .generate_suitable_session_key(as_req.req_body().etype())
            .ok_or(build_protocol_error(Ecode::KDC_ERR_ETYPE_NOSUPP))??;

        let selected_client_key = client_key;
        let kdc_options = as_req.req_body().kdc_options();

        let mut ticket_flags = self.generate_ticket_flags(as_req).unwrap();

        let mut ticket = EncTicketPart::builder();
        if let Some(addr) = as_req.req_body().addresses() {
            ticket.caddr(addr.clone());
        }
        let till = if as_req.req_body().till() == &KerberosTime::zero() {
            KerberosTime::infinity()
        } else {
            *as_req.req_body().till()
        };

        let mut starttime = None;

        if kdc_options.is_set(KdcOptionsFlag::POSTDATED as usize) {
            if self.against_postdate_policy(as_req.req_body().from()) {
                return Err(build_protocol_error(Ecode::KDC_ERR_POLICY));
            }
            ticket_flags.set(TicketFlag::INVALID as usize);
            starttime = Some(as_req.req_body().from().copied().unwrap_or(kdc_time));
        } else if starttime.is_some_and(|t| self.get_acceptable_clock_skew().contains(&t)) {
            return Err(build_protocol_error(Ecode::KDC_ERR_CANNOT_POSTDATE));
        }

        let endtime = *[
            till,
            starttime.unwrap_or(kdc_time) + client.max_lifetime,
            starttime.unwrap_or(kdc_time) + server.max_lifetime,
            // starttime + max_lifetime_for_realm
        ]
        .iter()
        .min()
        .expect("Won't fail");
        ticket.endtime(endtime);

        let rtime = if kdc_options.is_set(KdcOptionsFlag::RENEWABLE_OK as usize)
            && &endtime < as_req.req_body().till()
        {
            Some(as_req.req_body().till())
        } else {
            None
        }
        .map(|t| {
            if t == &KerberosTime::zero() {
                KerberosTime::infinity()
            } else {
                KerberosTime::zero()
            }
        });

        if let Some(rtime) = rtime {
            ticket_flags.set(TicketFlag::RENEWABLE as usize);
            ticket.renew_till(
                *[
                    rtime,
                    starttime.unwrap_or(kdc_time) + client.max_renewable_life,
                    starttime.unwrap_or(kdc_time) + server.max_renewable_life,
                    // starttime.unwrap_or(kdc_time) + max_rtime_for_realm
                ]
                .iter()
                .min()
                .expect("Should not fail"),
            );
        }

        ticket.starttime(starttime.unwrap_or(kdc_time));

        let ticket = ticket
            .flags(ticket_flags.build().unwrap())
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
            .build()
            .unwrap();

        let ticket = self
            .get_supported_crypto_systems()
            .iter()
            .find(|crypto| crypto.get_etype() == *server_key.keytype())
            .map(|crypto| {
                let enc = crypto
                    .encrypt(&ticket.to_der().unwrap(), server_key.keyvalue().as_bytes())
                    .unwrap();
                EncryptedData::new(crypto.get_etype(), None, OctetString::new(enc).unwrap())
            })
            .unwrap();

        let sname = as_req.req_body().sname().unwrap().clone();
        let srealm = as_req.req_body().realm().clone();

        let ticket = Ticket::new(srealm.clone(), sname.clone(), ticket);

        let mut enc_part = EncKdcRepPartBuilder::default();

        let enc_part = EncAsRepPart::new(
            enc_part
                .sname(sname)
                .srealm(srealm)
                .key(session_key)
                .last_req(vec![])
                .flags(ticket_flags.build().unwrap())
                .endtime(endtime)
                .starttime(starttime.unwrap_or(kdc_time))
                .authtime(kdc_time)
                .nonce(*as_req.req_body().nonce())
                .build()
                .unwrap(),
        );

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

    fn verify_encryption_type(&self, _as_req: &AsReq) -> Result<()> {
        Ok(())
    }

    // TODO: implement this correctly
    fn generate_ticket_flags(
        &self,
        as_req: &AsReq,
    ) -> std::result::Result<KerberosFlagsBuilder, Ecode> {
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

        Ok(ticket_flag)
    }

    // TODO: implement this correctly
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
        println!("{:?}", start_time);
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

    fn against_postdate_policy(&self, _p0: Option<&KerberosTime>) -> bool {
        // TODO: correctly implement this
        return false;
    }
}
