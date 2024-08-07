use der::Sequence;

use crate::{
    basic::{EncryptionKey, HostAddresses, KerberosTime, PrincipalName, Realm, UInt32},
    spec_as_tgs_exchange::last_req::LastReq,
    tickets::TicketFlags,
};

#[derive(Sequence)]
pub struct EncKdcRepPart {
    key: EncryptionKey,

    last_req: LastReq,

    nonce: UInt32,

    #[asn1(optional = "true")]
    key_expiration: Option<KerberosTime>,

    flags: TicketFlags,

    authtime: KerberosTime,

    #[asn1(optional = "true")]
    starttime: Option<KerberosTime>,

    endtime: KerberosTime,

    #[asn1(optional = "true")]
    renew_till: Option<KerberosTime>,

    srealm: Realm,

    sname: PrincipalName,

    #[asn1(optional = "true")]
    caddr: Option<HostAddresses>,
}

impl EncKdcRepPart {
    pub fn new(
        key: EncryptionKey,
        last_req: LastReq,
        nonce: UInt32,
        key_expiration: Option<KerberosTime>,
        flags: TicketFlags,
        authtime: KerberosTime,
        starttime: Option<KerberosTime>,
        endtime: KerberosTime,
        renew_till: Option<KerberosTime>,
        srealm: Realm,
        sname: PrincipalName,
        caddr: Option<HostAddresses>,
    ) -> Self {
        Self {
            key,
            last_req,
            nonce,
            key_expiration,
            flags,
            authtime,
            starttime,
            endtime,
            renew_till,
            srealm,
            sname,
            caddr,
        }
    }

    pub fn key(&self) -> &EncryptionKey {
        &self.key
    }

    pub fn last_req(&self) -> &LastReq {
        &self.last_req
    }

    pub fn nonce(&self) -> &UInt32 {
        &self.nonce
    }

    pub fn key_expiration(&self) -> Option<&KerberosTime> {
        self.key_expiration.as_ref()
    }

    pub fn flags(&self) -> &TicketFlags {
        &self.flags
    }

    pub fn authtime(&self) -> &KerberosTime {
        &self.authtime
    }

    pub fn starttime(&self) -> Option<&KerberosTime> {
        self.starttime.as_ref()
    }

    pub fn endtime(&self) -> &KerberosTime {
        &self.endtime
    }

    pub fn renew_till(&self) -> Option<&KerberosTime> {
        self.renew_till.as_ref()
    }

    pub fn srealm(&self) -> &Realm {
        &self.srealm
    }

    pub fn sname(&self) -> &PrincipalName {
        &self.sname
    }

    pub fn caddr(&self) -> Option<&HostAddresses> {
        self.caddr.as_ref()
    }
}
