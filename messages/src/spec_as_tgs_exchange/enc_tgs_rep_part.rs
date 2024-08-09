use crate::basic::application_tags;
use crate::spec_as_tgs_exchange::enc_kdc_rep_part::EncKdcRepPart;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, TagNumber,
    Writer,
};
use std::ops::Deref;

pub struct EncTgsRepPart(EncKdcRepPart);

impl EncTgsRepPart {
    pub fn new(inner: impl Into<EncKdcRepPart>) -> Self {
        Self(inner.into())
    }
}

impl<'a> DecodeValue<'a> for EncTgsRepPart {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = EncKdcRepPart::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for EncTgsRepPart {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl Deref for EncTgsRepPart {
    type Target = EncKdcRepPart;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FixedTag for EncTgsRepPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_TGS_REP_PART),
    };
}

#[cfg(test)]
mod tests {
    use crate::basic::application_tags;
    use crate::spec_as_tgs_exchange::enc_kdc_rep_part::tests;
    use crate::spec_as_tgs_exchange::enc_tgs_rep_part::EncTgsRepPart;
    use der::{Decode, Encode, EncodeValue, SliceReader, Tag, TagNumber, Tagged};

    pub fn sample_data() -> EncTgsRepPart {
        EncTgsRepPart::new(tests::sample_data())
    }

    #[test]
    fn test_tag() {
        let data = sample_data();
        let tag = Tag::Application {
            constructed: true,
            number: TagNumber::new(application_tags::ENC_TGS_REP_PART),
        };
        assert_eq!(data.tag(), tag);
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded =
            EncTgsRepPart::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded.header(), data.header());
    }
}
