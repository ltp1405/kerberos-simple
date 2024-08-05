use der::Sequence;

use crate::basic::{EncryptionKey, HostAddresses, KerberosTime, PrincipalName, Realm};
use crate::tickets::TicketFlags;

#[derive(Sequence)]
pub struct KrbCredInfo {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    key: EncryptionKey,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    prealm: Option<Realm>,

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pname: Option<PrincipalName>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    flags: Option<TicketFlags>,

    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", optional = "true")]
    authtime: Option<KerberosTime>,

    #[asn1(context_specific = "5", tag_mode = "EXPLICIT", optional = "true")]
    starttime: Option<KerberosTime>,

    #[asn1(context_specific = "6", tag_mode = "EXPLICIT", optional = "true")]
    endtime: Option<KerberosTime>,

    #[asn1(context_specific = "7", tag_mode = "EXPLICIT", optional = "true")]
    renew_till: Option<KerberosTime>,

    #[asn1(context_specific = "8", tag_mode = "EXPLICIT", optional = "true")]
    srealm: Option<Realm>,

    #[asn1(context_specific = "9", tag_mode = "EXPLICIT", optional = "true")]
    sname: Option<PrincipalName>,

    #[asn1(context_specific = "10", tag_mode = "EXPLICIT", optional = "true")]
    caddr: Option<HostAddresses>,
}

impl KrbCredInfo {
    pub fn new(
        key: impl Into<EncryptionKey>,
        prealm: impl Into<Option<Realm>>,
        pname: impl Into<Option<PrincipalName>>,
        flags: impl Into<Option<TicketFlags>>,
        authtime: impl Into<Option<KerberosTime>>,
        starttime: impl Into<Option<KerberosTime>>,
        endtime: impl Into<Option<KerberosTime>>,
        renew_till: impl Into<Option<KerberosTime>>,
        srealm: impl Into<Option<Realm>>,
        sname: impl Into<Option<PrincipalName>>,
        caddr: impl Into<Option<HostAddresses>>,
    ) -> Self {
        Self {
            key: key.into(),
            prealm: prealm.into(),
            pname: pname.into(),
            flags: flags.into(),
            authtime: authtime.into(),
            starttime: starttime.into(),
            endtime: endtime.into(),
            renew_till: renew_till.into(),
            srealm: srealm.into(),
            sname: sname.into(),
            caddr: caddr.into(),
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