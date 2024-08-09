use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, TagNumber,
    Writer,
};
use std::ops::Deref;

use crate::{
    basic::{application_tags, Int32, PaData, SequenceOf},
    spec_as_tgs_exchange::kdc_req::KdcReq,
    spec_as_tgs_exchange::kdc_req_body::KdcReqBody,
};

#[derive(Eq, PartialEq, Debug)]
pub struct TgsReq(KdcReq);

impl TgsReq {
    pub fn new(
        padata: impl Into<Option<SequenceOf<PaData>>>,
        req_body: impl Into<KdcReqBody>,
    ) -> Self {
        let msg_type = Int32::new(b"\x0C").expect("Cannot initialize Int32 from &[u8]");
        Self(KdcReq::new(msg_type, padata, req_body))
    }
}

impl<'a> DecodeValue<'a> for TgsReq {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = KdcReq::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for TgsReq {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl Deref for TgsReq {
    type Target = KdcReq;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FixedTag for TgsReq {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::TGS_REQ),
    };
}

#[cfg(test)]
mod tests {
    use crate::basic::{application_tags, Int32};
    use crate::spec_as_tgs_exchange::kdc_req_body;
    use crate::spec_as_tgs_exchange::tgs_req::TgsReq;
    use der::{Decode, Encode, EncodeValue, SliceReader, Tag, TagNumber, Tagged};

    fn sample_data() -> TgsReq {
        TgsReq::new(None, kdc_req_body::tests::sample_data())
    }

    #[test]
    fn test_primitives() {
        let data = sample_data();
        assert_eq!(*data.pvno(), Int32::new(b"\x05").unwrap());
        assert_eq!(*data.msg_type(), Int32::new(b"\x0C").unwrap());
        assert!(data.padata().is_none());
    }

    #[test]
    fn test_tag() {
        let data = sample_data();
        let tag = Tag::Application {
            constructed: true,
            number: TagNumber::new(application_tags::TGS_REQ),
        };
        assert_eq!(data.tag(), tag);

        assert_eq!(data.header().unwrap().tag, tag);
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded_data: TgsReq =
            TgsReq::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded_data, data);
    }
}
