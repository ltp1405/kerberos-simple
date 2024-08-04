use der::{FixedTag, Tag, TagNumber};
use crate::basic::application_tags;
use crate::spec_as_tgs_exchange::enc_kdc_rep_part::EncKdcRepPart;

pub struct EncAsRepPart {
    inner: EncKdcRepPart,
}

impl EncAsRepPart {
    pub fn new(inner: EncKdcRepPart) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &EncKdcRepPart {
        &self.inner
    }
}

impl FixedTag for EncAsRepPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_AS_REP_PART),
    };
}
