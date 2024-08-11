use der::Sequence;

use crate::{
    basic::{Int32, PaData, SequenceOf},
    spec_as_tgs_exchange::kdc_req_body::KdcReqBody,
};

#[derive(Sequence, Eq, PartialEq, Debug)]
pub struct KdcReq {
    #[asn1(context_specific = "1")]
    pvno: Int32,

    #[asn1(context_specific = "2")]
    msg_type: Int32,

    #[asn1(context_specific = "3", optional = "true")]
    padata: Option<SequenceOf<PaData>>,

    #[asn1(context_specific = "4")]
    req_body: KdcReqBody,
}

impl KdcReq {
    pub fn new(
        msg_type: impl Into<Int32>,
        padata: impl Into<Option<SequenceOf<PaData>>>,
        req_body: impl Into<KdcReqBody>,
    ) -> Self {
        let pvno = Int32::new(b"\x05").expect("Cannot initialize Int32 from &[u8]");
        Self {
            pvno,
            msg_type: msg_type.into(),
            padata: padata.into(),
            req_body: req_body.into(),
        }
    }

    pub fn pvno(&self) -> &Int32 {
        &self.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.msg_type
    }

    pub fn padata(&self) -> Option<&SequenceOf<PaData>> {
        self.padata.as_ref()
    }

    pub fn req_body(&self) -> &KdcReqBody {
        &self.req_body
    }
}

#[cfg(test)]
pub mod tests {
    use crate::basic::Int32;
    use crate::spec_as_tgs_exchange::{kdc_req::KdcReq, kdc_req_body::tests};
    use der::{Decode, Encode, EncodeValue, SliceReader};

    pub fn sample_data() -> KdcReq {
        KdcReq::new(Int32::new(b"\x01").unwrap(), None, tests::sample_data())
    }

    #[test]
    fn test_primitives() {
        let data = sample_data();
        assert_eq!(data.pvno(), &Int32::new(b"\x05").unwrap());
        assert_eq!(data.msg_type(), &Int32::new(b"\x01").unwrap());
        assert!(data.padata().is_none());
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded = KdcReq::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded.header(), data.header());
        assert_eq!(decoded, data);
    }
}
