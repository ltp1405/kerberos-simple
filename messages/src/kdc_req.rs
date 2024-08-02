use der::Sequence;

use crate::{
    basic::{Int32, PaData, SequenceOf, DEFAULT_PRINCIPAL_COMPONENTS_LEN},
    kdc_req_body::KdcReqBody,
};

#[derive(Sequence)]
pub struct KdcReq {
    #[asn1(context_specific = "1")]
    pvno: Int32,

    #[asn1(context_specific = "2")]
    msg_type: Int32,

    #[asn1(context_specific = "3", optional = "true")]
    padata: Option<SequenceOf<PaData, DEFAULT_PRINCIPAL_COMPONENTS_LEN>>,

    #[asn1(context_specific = "4")]
    req_body: KdcReqBody,
}

impl KdcReq {
    pub fn new(
        msg_type: Int32,
        padata: Option<SequenceOf<PaData, DEFAULT_PRINCIPAL_COMPONENTS_LEN>>,
        req_body: KdcReqBody,
    ) -> Self {
        let pvno = Int32::new(b"\x05").expect("Cannot initialize Int32 from &[u8]");
        Self {
            pvno,
            msg_type,
            padata,
            req_body,
        }
    }

    pub fn pvno(&self) -> &Int32 {
        &self.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.msg_type
    }

    pub fn padata(&self) -> Option<&SequenceOf<PaData, DEFAULT_PRINCIPAL_COMPONENTS_LEN>> {
        self.padata.as_ref()
    }

    pub fn req_body(&self) -> &KdcReqBody {
        &self.req_body
    }
}
