use crate::{
    basic::{
        EncryptedData, HostAddresses, Int32, KerberosTime, PrincipalName, Realm, SequenceOf, UInt32,
    },
    spec_as_tgs_exchange::kdc_options::KdcOptions,
    tickets::Ticket,
};
use der::Sequence;

#[derive(Sequence, Eq, PartialEq, Debug)]
pub struct KdcReqBody {
    #[asn1(context_specific = "0")]
    pub kdc_options: KdcOptions,

    #[asn1(context_specific = "1", optional = "true")]
    pub cname: Option<PrincipalName>,

    #[asn1(context_specific = "2")]
    pub realm: Realm,

    #[asn1(context_specific = "3", optional = "true")]
    pub sname: Option<PrincipalName>,

    #[asn1(context_specific = "4", optional = "true")]
    pub from: Option<KerberosTime>,

    #[asn1(context_specific = "5")]
    pub till: KerberosTime,

    #[asn1(context_specific = "6", optional = "true")]
    pub rtime: Option<KerberosTime>,

    #[asn1(context_specific = "7")]
    pub nonce: UInt32,

    #[asn1(context_specific = "8")]
    pub etype: SequenceOf<Int32>,

    #[asn1(context_specific = "9", optional = "true")]
    pub addresses: Option<HostAddresses>,

    #[asn1(context_specific = "10", optional = "true")]
    pub enc_authorization_data: Option<EncryptedData>,

    #[asn1(context_specific = "11", optional = "true")]
    pub additional_tickets: Option<SequenceOf<Ticket>>,
}

impl KdcReqBody {
    pub fn new(
        kdc_options: impl Into<KdcOptions>,
        cname: impl Into<Option<PrincipalName>>,
        realm: impl Into<Realm>,
        sname: impl Into<Option<PrincipalName>>,
        from: impl Into<Option<KerberosTime>>,
        till: impl Into<KerberosTime>,
        rtime: impl Into<Option<KerberosTime>>,
        nonce: impl Into<UInt32>,
        etype: impl Into<SequenceOf<Int32>>,
        addresses: impl Into<Option<HostAddresses>>,
        enc_authorization_data: impl Into<Option<EncryptedData>>,
        additional_tickets: impl Into<Option<SequenceOf<Ticket>>>,
    ) -> Self {
        Self {
            kdc_options: kdc_options.into(),
            cname: cname.into(),
            realm: realm.into(),
            sname: sname.into(),
            from: from.into(),
            till: till.into(),
            rtime: rtime.into(),
            nonce: nonce.into(),
            etype: etype.into(),
            addresses: addresses.into(),
            enc_authorization_data: enc_authorization_data.into(),
            additional_tickets: additional_tickets.into(),
        }
    }

    pub fn kdc_options(&self) -> &KdcOptions {
        &self.kdc_options
    }

    pub fn cname(&self) -> Option<&PrincipalName> {
        self.cname.as_ref()
    }

    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    pub fn sname(&self) -> Option<&PrincipalName> {
        self.sname.as_ref()
    }

    pub fn from(&self) -> Option<&KerberosTime> {
        self.from.as_ref()
    }

    pub fn till(&self) -> &KerberosTime {
        &self.till
    }

    pub fn rtime(&self) -> Option<&KerberosTime> {
        self.rtime.as_ref()
    }

    pub fn nonce(&self) -> &UInt32 {
        &self.nonce
    }

    pub fn etype(&self) -> &SequenceOf<Int32> {
        &self.etype
    }

    pub fn addresses(&self) -> Option<&HostAddresses> {
        self.addresses.as_ref()
    }

    pub fn enc_authorization_data(&self) -> Option<&EncryptedData> {
        self.enc_authorization_data.as_ref()
    }

    pub fn additional_tickets(&self) -> Option<&SequenceOf<Ticket>> {
        self.additional_tickets.as_ref()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::basic::{
        flags, KerberosFlags, KerberosString, NameTypes, OctetString, PrincipalName, Realm,
    };
    use der::{Decode, Encode, EncodeValue, SliceReader};
    use std::time::Duration;

    pub fn sample_data() -> KdcReqBody {
        KdcReqBody::new(
            KerberosFlags::builder()
                .set(flags::FORWARDABLE)
                .build()
                .unwrap(),
            Some(
                PrincipalName::new(
                    NameTypes::NtEnterprise,
                    vec![KerberosString::try_from("host".to_string()).unwrap()],
                )
                .unwrap(),
            ),
            Realm::new("EXAMPLE.COM").unwrap(),
            Some(
                PrincipalName::new(
                    NameTypes::NtPrincipal,
                    vec![KerberosString::try_from("krbtgt".to_string()).unwrap()],
                )
                .unwrap(),
            ),
            Some(KerberosTime::from_unix_duration(Duration::from_secs(1)).unwrap()),
            KerberosTime::from_unix_duration(Duration::from_secs(2)).unwrap(),
            Some(KerberosTime::from_unix_duration(Duration::from_secs(3)).unwrap()),
            3,
            SequenceOf::from(vec![1]),
            Some(HostAddresses::new()),
            Some(EncryptedData::new(1, 10, OctetString::new(b"key").unwrap())),
            Some(SequenceOf::from(vec![Ticket::new(
                Realm::new("EXAMPLE.COM").unwrap(),
                PrincipalName::new(
                    NameTypes::NtPrincipal,
                    vec![KerberosString::try_from("krbtgt".to_string()).unwrap()],
                )
                .unwrap(),
                EncryptedData::new(1, 10, OctetString::new(b"key").unwrap()),
            )])),
        )
    }

    #[test]
    fn test_primitives() {
        let body = sample_data();
        let mut compare = Vec::new();

        let kdc_options: [u8; 7] = [0x03, 0x05, 0x00, 0x40, 0x00, 0x00, 0x00];
        body.kdc_options().encode_to_vec(&mut compare).unwrap();
        assert_eq!(compare.len(), kdc_options.len());
        assert_eq!(compare, kdc_options);

        compare.clear();
        let realm: [u8; 13] = [
            0x16, 0x0B, 0x45, 0x58, 0x41, 0x4D, 0x50, 0x4C, 0x45, 0x2E, 0x43, 0x4F, 0x4D,
        ];
        body.realm().encode_to_vec(&mut compare).unwrap();
        assert_eq!(compare.len(), realm.len());
        assert_eq!(compare, realm);

        compare.clear();
        let from: [u8; 17] = [
            0x18, 0x0F, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x31, 0x5A,
        ];
        body.from().unwrap().encode_to_vec(&mut compare).unwrap();
        assert_eq!(compare.len(), from.len());
        assert_eq!(compare, from);

        compare.clear();
        let till: [u8; 17] = [
            0x18, 0x0F, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x32, 0x5A,
        ];
        body.till().encode_to_vec(&mut compare).unwrap();
        assert_eq!(compare.len(), till.len());
        assert_eq!(compare, till);

        compare.clear();
        let rtime: [u8; 17] = [
            0x18, 0x0F, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x33, 0x5A,
        ];
        body.rtime().unwrap().encode_to_vec(&mut compare).unwrap();
        assert_eq!(compare.len(), rtime.len());
        assert_eq!(compare, rtime);

        compare.clear();
        let nonce: [u8; 3] = [0x02, 0x01, 0x03];
        body.nonce().encode_to_vec(&mut compare).unwrap();
        assert_eq!(compare.len(), nonce.len());
        assert_eq!(compare, nonce);

        compare.clear();
        let etype: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x01];
        body.etype().encode_to_vec(&mut compare).unwrap();
        assert_eq!(compare.len(), etype.len());
        assert_eq!(compare, etype);
    }

    #[test]
    fn verify_encode_decode() {
        let body = sample_data();
        let mut buf = Vec::new();
        body.encode_to_vec(&mut buf).unwrap();
        let decoded =
            KdcReqBody::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded.header(), body.header());
        assert_eq!(decoded, body);
    }
}
