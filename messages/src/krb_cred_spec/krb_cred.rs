use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

use crate::basic::{application_tags, EncryptedData, Int32, SequenceOf};
use crate::tickets::Ticket;

#[derive(Sequence, Eq, PartialEq, Debug)]
pub struct KrbCredInner {
    #[asn1(context_specific = "0")]
    pvno: Int32,

    #[asn1(context_specific = "1")]
    msg_type: Int32,

    #[asn1(context_specific = "2")]
    tickets: SequenceOf<Ticket>,

    #[asn1(context_specific = "3")]
    enc_part: EncryptedData,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KrbCred(KrbCredInner);

impl KrbCred {
    pub fn new(tickets: impl Into<SequenceOf<Ticket>>, enc_part: impl Into<EncryptedData>) -> Self {
        let pvno = Int32::new(b"\x05").expect("Cannot initialize Int32 from &[u8]");
        let msg_type = Int32::new(b"\x16").expect("Cannot initialize Int32 from &[u8]");
        let inner = KrbCredInner {
            pvno: pvno.into(),
            msg_type: msg_type.into(),
            tickets: tickets.into(),
            enc_part: enc_part.into(),
        };

        Self(inner)
    }

    pub fn pvno(&self) -> &Int32 {
        &self.0.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.0.msg_type
    }

    pub fn tickets(&self) -> &SequenceOf<Ticket> {
        &self.0.tickets
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.0.enc_part
    }
}

impl<'a> DecodeValue<'a> for KrbCred {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = KrbCredInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for KrbCred {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for KrbCred {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::KRB_CRED),
    };
}

#[cfg(test)]
mod tests {
    use crate::basic::{application_tags, EncryptedData, Int32, OctetString};
    use crate::krb_cred_spec::krb_cred::KrbCred;
    use der::{Decode, Encode, SliceReader, Tag, TagNumber, Tagged};

    pub fn sample_data() -> KrbCred {
        KrbCred::new(
            vec![],
            EncryptedData::new(
                Int32::new(b"\xAB").unwrap(),
                Some(Int32::new(b"\x01").unwrap()),
                OctetString::new("".as_bytes()).unwrap(),
            ),
        )
    }

    #[test]
    fn test_primitives() {
        let data = sample_data();
        assert_eq!(*data.pvno(), Int32::new(b"\x05").unwrap());
        assert_eq!(*data.msg_type(), Int32::new(b"\x16").unwrap());
        assert!(data.tickets().is_empty());
    }

    #[test]
    fn test_tag() {
        let data = sample_data();
        let tag = Tag::Application {
            constructed: true,
            number: TagNumber::new(application_tags::KRB_CRED),
        };
        assert_eq!(data.tag(), tag);
    }

    #[test]
    fn test_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded = KrbCred::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(data, decoded);
    }
}
