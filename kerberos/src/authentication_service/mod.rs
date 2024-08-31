use crate::cryptography::Cryptography;
use messages::basic_types::{
    EncryptedData, HostAddresses, Int32, KerberosTime, Microseconds, OctetString, PrincipalName,
    Realm,
};
use messages::flags::TicketFlag;
use messages::Decode;
use messages::{
    ApRep, ApReq, AsRep, AsReq, Authenticator, AuthenticatorBuilder, Ecode, EncTicketPart, Encode,
};
use std::error::Error;
use std::time::{Duration, SystemTime};

pub struct ServerConfig {
    pub accept_empty_address_ticket: bool,
    pub ticket_allowable_clock_skew: Duration,
}

pub struct AuthenticationService<'a, C, K, Crypto>
where
    C: ReplayCache,
    K: KeyFinder,
    Crypto: Cryptography,
{
    pub accept_empty_address_ticket: bool,
    pub ticket_allowable_clock_skew: Duration,
    replay_cache: &'a C,
    key_finder: &'a K,
    crypto: &'a Crypto,
}

#[derive(Debug)]
enum ServerError {
    ClientPrincipalNameNotFound,
    ServerPrincipalNameNotFound,
    BadKeyVersion,
    ApNoKey,
    CannotDecode,
    ApBadAddress,
    ApSkew,
    Internal,
    ApTicketInvalid,
    ApTicketExpired,
}

impl From<ServerError> for Ecode {
    fn from(value: ServerError) -> Self {
        match value {
            ServerError::ClientPrincipalNameNotFound => Ecode::KDC_ERR_C_PRINCIPAL_UNKNOWN,
            ServerError::ServerPrincipalNameNotFound => Ecode::KDC_ERR_S_PRINCIPAL_UNKNOWN,
            _ => panic!(),
        }
    }
}

pub trait PrincipalDatabase {
    fn get_client_principal_key(&self, principal_name: &PrincipalName) -> Option<String>;
    fn get_server_principal_key(&self, principal_name: &PrincipalName) -> Option<String>;
}

pub trait KeyFinder {
    fn get_key_for_srealm(&self, srealm: &Realm) -> Option<Vec<u8>>;
}

fn handle_krb_as_req(db: &impl PrincipalDatabase, as_req: AsReq) -> Result<AsRep, ServerError> {
    db.get_client_principal_key(
        as_req
            .req_body()
            .cname()
            .ok_or(ServerError::ClientPrincipalNameNotFound)?,
    );

    db.get_server_principal_key(
        as_req
            .req_body()
            .cname()
            .ok_or(ServerError::ServerPrincipalNameNotFound)?,
    );
    unimplemented!();
}

pub trait ClientAddressFinder {
    fn find_client_address();
}

struct ReplayCacheEntry {
    server_name: PrincipalName,
    client_name: PrincipalName,
    time: KerberosTime,
    microseconds: Microseconds,
}

pub trait ReplayCache {
    type ReplayCacheError: Error;
    fn store(&self, entry: ReplayCacheEntry) -> Result<(), ReplayCacheEntry>;
    fn contain(&self, entry: ReplayCacheEntry) -> Result<bool, ReplayCacheEntry>;
}

fn handle_krb_ap_req(
    replay_cache: &impl ReplayCache,
    key_finder: &impl KeyFinder,
    crypto: &impl Cryptography,
    ap_req: ApReq,
    server_config: ServerConfig,
) -> Result<ApRep, ServerError> {
    if verify_key(ap_req.ticket().tkt_vno()) {
        return Err(ServerError::BadKeyVersion);
    }

    let key = key_finder
        .get_key_for_srealm(ap_req.ticket().realm())
        .ok_or(ServerError::ApNoKey)?;

    let decrypted = crypto
        .decrypt(ap_req.ticket().enc_part().cipher().as_bytes(), &key)
        .map_err(|_| ServerError::CannotDecode)?;
    // TODO: check for decrypted msg's integrity

    let ticket = EncTicketPart::from_der(&decrypted).map_err(|_| ServerError::CannotDecode)?;

    let ss_key = ticket.key().keyvalue().as_bytes();

    let decrypted = crypto
        .decrypt(ap_req.authenticator().cipher().as_bytes(), &ss_key)
        .map_err(|_| ServerError::CannotDecode)?;

    let authenticator =
        Authenticator::from_der(&decrypted).map_err(|_| ServerError::CannotDecode)?;

    ticket
        .caddr()
        .take_if(|a| !a.is_empty())
        .ok_or(ServerError::ApBadAddress)
        .map(|addresses| search_for_addresses(addresses))?
        .then_some(())
        .ok_or(ServerError::ApBadAddress)?;

    let ticket_time = ticket.starttime().unwrap_or(ticket.authtime());
    let local_time =
        KerberosTime::from_system_time(SystemTime::now()).map_err(|_| ServerError::Internal)?;

    ticket
        .flags()
        .is_set(TicketFlag::INVALID as usize)
        .then_some(ServerError::ApTicketInvalid)
        .map(Err)
        .unwrap_or(Ok(()))
        .and(valid_ticket_time(
            &ticket_time,
            &local_time,
            server_config.ticket_allowable_clock_skew,
        ))?;

    replay_cache
        .store(ReplayCacheEntry {
            server_name: ap_req.ticket().sname().clone(),
            client_name: ticket.cname().clone(),
            time: authenticator.ctime(),
            microseconds: authenticator.cusec(),
        })
        .map_err(|_| ServerError::Internal)?;

    let rep_authenticator = AuthenticatorBuilder::default()
        .ctime(authenticator.ctime())
        .cusec(authenticator.cusec())
        .build()
        .unwrap()
        .to_der()
        .map_err(|_| ServerError::Internal)?;

    let encrypted = crypto
        .encrypt(&rep_authenticator, ticket.key().keyvalue().as_bytes())
        .map_err(|_| ServerError::Internal)?;

    Ok(ApRep::new(EncryptedData::new(
        *ap_req.ticket().enc_part().etype(),
        ap_req.ticket().enc_part().kvno().map(|v| *v),
        OctetString::new(encrypted).map_err(|_| ServerError::Internal)?,
    )))

    // NOTE: Sequence number in authenticator is not handled because we do not
    // implement KRB_PRIV or KRB_SAFE
}

fn get_local_server_time() -> i32 {
    unimplemented!()
}

fn valid_ticket_time(
    ticket_time: &KerberosTime,
    local_time: &KerberosTime,
    server_allow_clock_skew: Duration,
) -> Result<(), ServerError> {
    let local_time = local_time.to_unix_duration();
    let ticket_time = ticket_time.to_unix_duration();
    if local_time > ticket_time {
        let skew = local_time - ticket_time;
        if skew > server_allow_clock_skew {
            return Err(ServerError::ApTicketInvalid);
        }
    } else {
        let skew = ticket_time - local_time;
        if skew > server_allow_clock_skew {
            return Err(ServerError::ApTicketExpired);
        }
    };
    Ok(())
}

fn search_for_addresses(host_addresses: &HostAddresses) -> bool {
    unimplemented!()
}

fn verify_key(p0: &Int32) -> bool {
    todo!()
}
