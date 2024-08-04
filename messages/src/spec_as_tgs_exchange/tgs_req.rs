use der::{FixedTag, Tag, TagNumber};

use crate::{
    basic::{Int32, PaData, SequenceOf},
    spec_as_tgs_exchange::kdc_req::KdcReq,
    spec_as_tgs_exchange::kdc_req_body::KdcReqBody,
};
use crate::basic::application_tags;

pub struct TgsReq {
    inner: KdcReq,
}

impl TgsReq {
    pub fn new(
        padata: Option<SequenceOf<PaData>>,
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
        number: TagNumber::new(application_tags::TGS_REQ),
    };
}
