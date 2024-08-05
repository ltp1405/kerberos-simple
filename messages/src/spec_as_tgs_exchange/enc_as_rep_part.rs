use crate::basic::application_tags;
use crate::spec_as_tgs_exchange::enc_kdc_rep_part::EncKdcRepPart;
use der::{FixedTag, Tag, TagNumber};
use std::ops::Deref;

pub struct EncAsRepPart(EncKdcRepPart);
impl EncAsRepPart {
    pub fn new(inner: impl Into<EncKdcRepPart>) -> Self {
        Self(inner.into())
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
