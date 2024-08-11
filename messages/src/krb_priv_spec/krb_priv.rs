use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

use crate::basic::Int32;
use crate::basic::{application_tags, EncryptedData};

#[derive(Sequence, Eq, PartialEq, Debug)]
// Missing Application tag
pub struct KrbPrivInner {
    #[asn1(context_specific = "0")]
    pvno: Int32,

    #[asn1(context_specific = "1")]
    msg_type: Int32,

    #[asn1(context_specific = "3")]
    enc_part: EncryptedData,
}

pub struct KrbPriv(KrbPrivInner);

impl KrbPriv {
    pub fn new(
        pvno: impl Into<Int32>,
        msg_type: impl Into<Int32>,
        enc_part: impl Into<EncryptedData>,
    ) -> Self {
        Self(KrbPrivInner {
            pvno: pvno.into(),
            msg_type: msg_type.into(),
            enc_part: enc_part.into(),
        })
    }

    pub fn pvno(&self) -> &Int32 {
        &self.0.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.0.msg_type
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.0.enc_part
    }
}

impl<'a> DecodeValue<'a> for KrbPriv {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = KrbPrivInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for KrbPriv {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for KrbPriv {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::KRB_PRIV),
    };
}

#[cfg(test)]
mod tests {
    use crate::basic::{application_tags, EncryptedData, Int32, OctetString};
    use crate::krb_priv_spec::krb_priv::KrbPriv;
    use der::{Decode, Encode, EncodeValue, SliceReader, Tag, TagNumber, Tagged};

    pub fn sample_data() -> KrbPriv {
        KrbPriv::new(
            5,
            15,
            EncryptedData::new(171, Some(1), OctetString::new("".as_bytes()).unwrap()),
        )
    }

    #[test]
    fn test_primitives() {
        let data = sample_data();
        assert_eq!(*data.pvno(), 5);
        assert_eq!(*data.msg_type(), 15);
    }

    #[test]
    fn test_tag() {
        let data = sample_data();
        let tag = Tag::Application {
            constructed: true,
            number: TagNumber::new(application_tags::KRB_PRIV),
        };
        assert_eq!(data.tag(), tag);
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded = KrbPriv::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded.header(), data.header());
    }
}
