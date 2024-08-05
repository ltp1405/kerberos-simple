use std::ops::Deref;
use der::{FixedTag, Tag, TagNumber};
use crate::basic::application_tags;
use crate::spec_as_tgs_exchange::enc_kdc_rep_part::EncKdcRepPart;

pub struct EncTgsRepPart(EncKdcRepPart);

impl EncTgsRepPart {
    pub fn new(inner: impl Into<EncKdcRepPart>) -> Self {
        Self(inner.into())
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
