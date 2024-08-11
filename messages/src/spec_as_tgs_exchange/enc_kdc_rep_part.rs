use der::Sequence;

use crate::{
    basic::{EncryptionKey, HostAddresses, KerberosTime, PrincipalName, Realm, UInt32},
    spec_as_tgs_exchange::last_req::LastReq,
    tickets::TicketFlags,
};

#[derive(Sequence, Eq, PartialEq, Debug)]
pub struct EncKdcRepPart {
    #[asn1(context_specific = "0")]
    key: EncryptionKey,

    #[asn1(context_specific = "1")]
    last_req: LastReq,

    #[asn1(context_specific = "2")]
    nonce: UInt32,

    #[asn1(context_specific = "3", optional = "true")]
    key_expiration: Option<KerberosTime>,

    #[asn1(context_specific = "4")]
    flags: TicketFlags,

    #[asn1(context_specific = "5")]
    authtime: KerberosTime,

    #[asn1(context_specific = "6", optional = "true")]
    starttime: Option<KerberosTime>,

    #[asn1(context_specific = "7")]
    endtime: KerberosTime,

    #[asn1(context_specific = "8", optional = "true")]
    renew_till: Option<KerberosTime>,

    #[asn1(context_specific = "9")]
    srealm: Realm,

    #[asn1(context_specific = "10")]
    sname: PrincipalName,

    #[asn1(context_specific = "11", optional = "true")]
    caddr: Option<HostAddresses>,
}

impl EncKdcRepPart {
    pub fn new(
        key: impl Into<EncryptionKey>,
        last_req: impl Into<LastReq>,
        nonce: impl Into<UInt32>,
        key_expiration: impl Into<Option<KerberosTime>>,
        flags: impl Into<TicketFlags>,
        authtime: impl Into<KerberosTime>,
        starttime: impl Into<Option<KerberosTime>>,
        endtime: impl Into<KerberosTime>,
        renew_till: impl Into<Option<KerberosTime>>,
        srealm: impl Into<Realm>,
        sname: impl Into<PrincipalName>,
        caddr: impl Into<Option<HostAddresses>>,
    ) -> Self {
        Self {
            key: key.into(),
            last_req: last_req.into(),
            nonce: nonce.into(),
            key_expiration: key_expiration.into(),
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

#[cfg(test)]
pub mod tests {
    use crate::basic::{
        flags, EncryptionKey, KerberosString, KerberosTime, NameTypes, PrincipalName, Realm,
    };
    use crate::spec_as_tgs_exchange::enc_kdc_rep_part::EncKdcRepPart;
    use crate::spec_as_tgs_exchange::last_req::LastReq;
    use crate::tickets::TicketFlags;
    use der::asn1::OctetString;
    use der::{Decode, Encode, SliceReader};
    use std::time::Duration;

    pub fn sample_data() -> EncKdcRepPart {
        EncKdcRepPart::new(
            EncryptionKey::new(171, OctetString::new(b"keyvalue").unwrap()),
            LastReq::new(),
            1,
            None,
            TicketFlags::builder()
                .set(flags::FORWARDABLE)
                .build()
                .unwrap(),
            KerberosTime::from_unix_duration(Duration::from_secs(0)).unwrap(),
            None,
            KerberosTime::from_unix_duration(Duration::from_secs(10)).unwrap(),
            None,
            Realm::new("EXAMPLE.COM".as_bytes()).unwrap(),
            PrincipalName::new(
                NameTypes::NtPrincipal,
                vec![KerberosString::new("krbtgt".as_bytes()).unwrap()],
            )
            .unwrap(),
            None,
        )
    }

    #[test]
    fn test_primitives() {
        let data = sample_data();
        assert_eq!(*data.key().keytype(), 171);
        assert_eq!(
            *data.key().keyvalue(),
            OctetString::new(b"keyvalue").unwrap()
        );
        assert_eq!(*data.nonce(), 1);
        assert_eq!(
            *data.flags(),
            TicketFlags::builder()
                .set(flags::FORWARDABLE)
                .build()
                .unwrap()
        );
        assert_eq!(
            *data.srealm(),
            Realm::new("EXAMPLE.COM".as_bytes()).unwrap()
        );
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded_data: EncKdcRepPart =
            EncKdcRepPart::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded_data, data);
    }
}
