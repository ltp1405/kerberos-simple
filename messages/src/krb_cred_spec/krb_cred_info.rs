use der::Sequence;

use crate::basic::{EncryptionKey, HostAddresses, KerberosTime, PrincipalName, Realm};
use crate::tickets::TicketFlags;

#[derive(Sequence)]
pub struct KrbCredInfo {
    key: EncryptionKey,

    #[asn1(optional = "true")]
    prealm: Option<Realm>,

    #[asn1(optional = "true")]
    pname: Option<PrincipalName>,

    #[asn1(optional = "true")]
    flags: Option<TicketFlags>,

    #[asn1(optional = "true")]
    authtime: Option<KerberosTime>,

    #[asn1(optional = "true")]
    starttime: Option<KerberosTime>,

    #[asn1(optional = "true")]
    endtime: Option<KerberosTime>,

    #[asn1(optional = "true")]
    renew_till: Option<KerberosTime>,

    #[asn1(optional = "true")]
    srealm: Option<Realm>,

    #[asn1(optional = "true")]
    sname: Option<PrincipalName>,

    #[asn1(optional = "true")]
    caddr: Option<HostAddresses>,
}

impl KrbCredInfo {
    pub fn new(
        key: EncryptionKey,
        prealm: Option<Realm>,
        pname: Option<PrincipalName>,
        flags: Option<TicketFlags>,
        authtime: Option<KerberosTime>,
        starttime: Option<KerberosTime>,
        endtime: Option<KerberosTime>,
        renew_till: Option<KerberosTime>,
        srealm: Option<Realm>,
        sname: Option<PrincipalName>,
        caddr: Option<HostAddresses>,
    ) -> Self {
        Self {
            key,
            prealm,
            pname,
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

    pub fn prealm(&self) -> Option<&Realm> {
        self.prealm.as_ref()
    }

    pub fn pname(&self) -> Option<&PrincipalName> {
        self.pname.as_ref()
    }

    pub fn flags(&self) -> Option<&TicketFlags> {
        self.flags.as_ref()
    }

    pub fn authtime(&self) -> Option<&KerberosTime> {
        self.authtime.as_ref()
    }

    pub fn starttime(&self) -> Option<&KerberosTime> {
        self.starttime.as_ref()
    }

    pub fn endtime(&self) -> Option<&KerberosTime> {
        self.endtime.as_ref()
    }

    pub fn renew_till(&self) -> Option<&KerberosTime> {
        self.renew_till.as_ref()
    }

    pub fn srealm(&self) -> Option<&Realm> {
        self.srealm.as_ref()
    }

    pub fn sname(&self) -> Option<&PrincipalName> {
        self.sname.as_ref()
    }

    pub fn caddr(&self) -> Option<&HostAddresses> {
        self.caddr.as_ref()
    }
}
