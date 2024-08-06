use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

use crate::basic::{
    application_tags, HostAddress, KerberosTime, Microseconds, OctetString, UInt32,
};
#[derive(Sequence)]
struct EncKrbPrivPartInner {
    #[asn1(context_specific = "0")]
    user_data: OctetString,

    #[asn1(context_specific = "1", optional = "true")]
    timestamp: Option<KerberosTime>,

    #[asn1(context_specific = "2", optional = "true")]
    usec: Option<Microseconds>,

    #[asn1(context_specific = "3", optional = "true")]
    seq_number: Option<UInt32>,

    #[asn1(context_specific = "4")]
    s_address: HostAddress,

    #[asn1(context_specific = "5", optional = "true")]
    r_address: Option<HostAddress>,
}

pub struct EncKrbPrivPart(EncKrbPrivPartInner);

impl EncKrbPrivPart {
    pub fn new(
        user_data: impl Into<OctetString>,
        timestamp: impl Into<Option<KerberosTime>>,
        usec: impl Into<Option<Microseconds>>,
        seq_number: impl Into<Option<UInt32>>,
        s_address: impl Into<HostAddress>,
        r_address: impl Into<Option<HostAddress>>,
    ) -> Self {
        Self(EncKrbPrivPartInner {
            user_data: user_data.into(),
            timestamp: timestamp.into(),
            usec: usec.into(),
            seq_number: seq_number.into(),
            s_address: s_address.into(),
            r_address: r_address.into(),
        })
    }

    pub fn user_data(&self) -> &OctetString {
        &self.0.user_data
    }

    pub fn timestamp(&self) -> Option<&KerberosTime> {
        self.0.timestamp.as_ref()
    }

    pub fn usec(&self) -> Option<&Microseconds> {
        self.0.usec.as_ref()
    }

    pub fn seq_number(&self) -> Option<&UInt32> {
        self.0.seq_number.as_ref()
    }

    pub fn s_address(&self) -> &HostAddress {
        &self.0.s_address
    }

    pub fn r_address(&self) -> Option<&HostAddress> {
        self.0.r_address.as_ref()
    }
}

impl<'a> DecodeValue<'a> for EncKrbPrivPart {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let inner = EncKrbPrivPartInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for EncKrbPrivPart {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for EncKrbPrivPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_KRB_PRIV_PART),
    };
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    mod tests {
        use crate::basic::predefined_values::AddressType;
        use crate::basic::{application_tags, EncryptedData, HostAddress, Int32};
        use crate::krb_priv_spec::enc_krb_priv_part::{EncKrbPrivPart, EncKrbPrivPartInner};
        use der::asn1::OctetString;
        use der::{Decode, Encode, EncodeValue, SliceReader, Tag, TagNumber, Tagged};

        pub fn sample_data() -> EncKrbPrivPart {
            EncKrbPrivPart::new(
                OctetString::new(b"hello").unwrap(),
                None,
                None,
                None,
                HostAddress::new(
                    AddressType::IPv4,
                    OctetString::new("192.168.0.10".as_bytes()).unwrap(),
                ),
                None,
            )
        }

        #[test]
        fn test_primitives() {
            let data = sample_data();
            assert_eq!(*data.user_data(), OctetString::new(b"hello").unwrap());
            assert!(data.timestamp().is_none());
            assert!(data.usec().is_none());
            assert!(data.seq_number().is_none());
            assert_eq!(
                *data.s_address(),
                HostAddress::new(
                    AddressType::IPv4,
                    OctetString::new("192.168.0.10".as_bytes()).unwrap(),
                )
            );
            assert!(data.r_address().is_none());
        }

        #[test]
        fn test_tag() {
            let data = sample_data();
            let tag = Tag::Application {
                constructed: true,
                number: TagNumber::new(application_tags::ENC_KRB_PRIV_PART),
            };
            assert_eq!(data.tag(), tag);
        }

        #[test]
        fn verify_encode_decode() {
            let data = sample_data();
            let mut buf = Vec::new();
            data.encode_to_vec(&mut buf).unwrap();
            let decoded =
                EncKrbPrivPart::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
            assert_eq!(decoded.header(), data.header());
        }
    }
}
