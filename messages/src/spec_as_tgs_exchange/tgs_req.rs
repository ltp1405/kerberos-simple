use std::ops::Deref;
use der::{FixedTag, Tag, TagNumber};

use crate::{
    basic::{Int32, PaData, SequenceOf, application_tags},
    spec_as_tgs_exchange::kdc_req::KdcReq,
    spec_as_tgs_exchange::kdc_req_body::KdcReqBody,
};

pub struct TgsReq(KdcReq);

impl TgsReq {
    pub fn new(
        padata: Option<SequenceOf<PaData>>,
        req_body: KdcReqBody,
    ) -> Self {
        let msg_type = Int32::new(b"\x0C").expect("Cannot initialize Int32 from &[u8]");
        Self(KdcReq::new(msg_type, padata, req_body))
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
