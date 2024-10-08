use der::Sequence;

use crate::basic::{EncryptionKey, HostAddresses, KerberosTime, PrincipalName, Realm};
use crate::tickets::TicketFlags;

#[derive(Sequence, Eq, PartialEq, Debug)]
pub struct KrbCredInfo {
    #[asn1(context_specific = "0")]
    key: EncryptionKey,

    #[asn1(context_specific = "1", optional = "true")]
    prealm: Option<Realm>,

    #[asn1(context_specific = "2", optional = "true")]
    pname: Option<PrincipalName>,

    #[asn1(context_specific = "3", optional = "true")]
    flags: Option<TicketFlags>,

    #[asn1(context_specific = "4", optional = "true")]
    authtime: Option<KerberosTime>,

    #[asn1(context_specific = "5", optional = "true")]
    starttime: Option<KerberosTime>,

    #[asn1(context_specific = "6", optional = "true")]
    endtime: Option<KerberosTime>,

    #[asn1(context_specific = "7", optional = "true")]
    renew_till: Option<KerberosTime>,

    #[asn1(context_specific = "8", optional = "true")]
    srealm: Option<Realm>,

    #[asn1(context_specific = "9", optional = "true")]
    sname: Option<PrincipalName>,

    #[asn1(context_specific = "10", optional = "true")]
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

#[cfg(test)]
mod tests {
    use crate::basic::{EncryptionKey, OctetString};
    use crate::krb_cred_spec::krb_cred_info::KrbCredInfo;
    use der::{Decode, Encode, SliceReader};

    pub fn sample_data() -> KrbCredInfo {
        KrbCredInfo::new(
            EncryptionKey::new(171, OctetString::new(b"key").unwrap()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn test_primitives() {
        let data = sample_data();
        assert_eq!(*data.key().keytype(), 171);
        assert_eq!(data.key().keyvalue().as_ref(), b"key");
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded =
            KrbCredInfo::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(data, decoded);
    }
}
