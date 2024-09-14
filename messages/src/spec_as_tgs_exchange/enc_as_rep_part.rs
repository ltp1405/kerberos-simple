use crate::basic::application_tags;
use crate::spec_as_tgs_exchange::enc_kdc_rep_part::EncKdcRepPart;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, TagNumber,
    Writer,
};
use std::ops::Deref;

#[derive(Clone, Debug)]
pub struct EncAsRepPart(pub EncKdcRepPart);
impl EncAsRepPart {
    pub fn new(inner: impl Into<EncKdcRepPart>) -> Self {
        Self(inner.into())
    }
}

impl<'a> DecodeValue<'a> for EncAsRepPart {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = EncKdcRepPart::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for EncAsRepPart {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl Deref for EncAsRepPart {
    type Target = EncKdcRepPart;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FixedTag for EncAsRepPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_AS_REP_PART),
    };
}

#[cfg(test)]
mod tests {
    use crate::basic::application_tags;
    use crate::spec_as_tgs_exchange::enc_as_rep_part::EncAsRepPart;
    use crate::spec_as_tgs_exchange::enc_kdc_rep_part::tests;
    use der::{Decode, Encode, EncodeValue, SliceReader, Tag, TagNumber, Tagged};

    pub fn sample_data() -> EncAsRepPart {
        EncAsRepPart::new(tests::sample_data())
    }

    #[test]
    fn test_tag() {
        let data = sample_data();
        let tag = Tag::Application {
            constructed: true,
            number: TagNumber::new(application_tags::ENC_AS_REP_PART),
        };
        assert_eq!(data.tag(), tag);
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded =
            EncAsRepPart::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded.header(), data.header());
    }
}
