use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

use crate::basic::{application_tags, HostAddress, KerberosTime, Microseconds, SequenceOf, UInt32};
use crate::krb_cred_spec::krb_cred_info::KrbCredInfo;

#[derive(Sequence, Eq, PartialEq, Debug)]
pub struct EncKrbCredPartInner {
    #[asn1(context_specific = "0")]
    ticket_info: SequenceOf<KrbCredInfo>,

    #[asn1(context_specific = "1", optional = "true")]
    nonce: Option<UInt32>,

    #[asn1(context_specific = "2", optional = "true")]
    timestamp: Option<KerberosTime>,

    #[asn1(context_specific = "3", optional = "true")]
    usec: Option<Microseconds>,

    #[asn1(context_specific = "4", optional = "true")]
    s_address: Option<HostAddress>,

    #[asn1(context_specific = "5", optional = "true")]
    r_address: Option<HostAddress>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EncKrbCredPart(EncKrbCredPartInner);

impl EncKrbCredPart {
    pub fn new(
        ticket_info: impl Into<SequenceOf<KrbCredInfo>>,
        nonce: impl Into<Option<UInt32>>,
        timestamp: impl Into<Option<KerberosTime>>,
        usec: impl Into<Option<Microseconds>>,
        s_address: impl Into<Option<HostAddress>>,
        r_address: impl Into<Option<HostAddress>>,
    ) -> Self {
        let inner = EncKrbCredPartInner {
            ticket_info: ticket_info.into(),
            nonce: nonce.into(),
            timestamp: timestamp.into(),
            usec: usec.into(),
            s_address: s_address.into(),
            r_address: r_address.into(),
        };

        Self(inner)
    }

    pub fn ticket_info(&self) -> &SequenceOf<KrbCredInfo> {
        &self.0.ticket_info
    }

    pub fn nonce(&self) -> Option<&UInt32> {
        self.0.nonce.as_ref()
    }

    pub fn timestamp(&self) -> Option<&KerberosTime> {
        self.0.timestamp.as_ref()
    }

    pub fn usec(&self) -> Option<&Microseconds> {
        self.0.usec.as_ref()
    }

    pub fn s_address(&self) -> Option<&HostAddress> {
        self.0.s_address.as_ref()
    }

    pub fn r_address(&self) -> Option<&HostAddress> {
        self.0.r_address.as_ref()
    }
}

impl<'a> DecodeValue<'a> for EncKrbCredPart {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = EncKrbCredPartInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for EncKrbCredPart {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for EncKrbCredPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_KRB_CRED_PART),
    };
}

#[cfg(test)]
mod tests {
    use crate::basic::application_tags;
    use crate::krb_cred_spec::enc_krb_cred_part::EncKrbCredPart;
    use der::{Decode, Encode, SliceReader, Tag, TagNumber, Tagged};

    pub fn sample_data() -> EncKrbCredPart {
        EncKrbCredPart::new(vec![], None, None, None, None, None)
    }

    #[test]
    fn test_tag() {
        let data = sample_data();
        let tag = Tag::Application {
            constructed: true,
            number: TagNumber::new(application_tags::ENC_KRB_CRED_PART),
        };
        assert_eq!(data.tag(), tag);
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded =
            EncKrbCredPart::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(data, decoded);
    }
}
