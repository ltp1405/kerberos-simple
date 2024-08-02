use der::{FixedTag, Tag, TagNumber};

use crate::{
    basic::{Int32, PaData, SequenceOf, DEFAULT_PRINCIPAL_COMPONENTS_LEN},
    kdc_req::KdcReq,
    kdc_req_body::KdcReqBody,
};

pub struct TgsReq {
    inner: KdcReq,
}

impl TgsReq {
    pub fn new(
        padata: Option<SequenceOf<PaData, DEFAULT_PRINCIPAL_COMPONENTS_LEN>>,
        req_body: KdcReqBody,
    ) -> Self {
        let msg_type = Int32::new(b"\x0C").expect("Cannot initialize Int32 from &[u8]");
        let inner = KdcReq::new(msg_type, padata, req_body);
        Self { inner }
    }

    pub fn inner(&self) -> &KdcReq {
        &self.inner
    }
}

impl FixedTag for TgsReq {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(12),
    };
}
