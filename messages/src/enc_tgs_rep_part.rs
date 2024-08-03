use der::{FixedTag, Tag, TagNumber};

use crate::enc_kdc_rep_part::EncKdcRepPart;

pub struct EncTgsRepPart {
    inner: EncKdcRepPart,
}

impl EncTgsRepPart {
    pub fn new(inner: EncKdcRepPart) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &EncKdcRepPart {
        &self.inner
    }
}

impl FixedTag for EncTgsRepPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(26),
    };
}
