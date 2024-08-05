use std::ops::Deref;
use der::{FixedTag, Sequence, Tag, TagNumber};

use crate::basic::{application_tags, EncryptedData};
use crate::basic::Int32;

#[derive(Sequence)]
// Missing Application tag
pub struct KrbPrivInner {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pvno: Int32,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    msg_type: Int32,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
    enc_part: EncryptedData,
}

pub struct KrbPriv(KrbPrivInner);

impl KrbPriv {
    pub fn new(pvno: Int32, msg_type: Int32, enc_part: EncryptedData) -> Self {
        Self(KrbPrivInner {
            pvno,
            msg_type,
            enc_part,
        })
    }

    pub fn pvno(&self) -> &Int32 {
        &self.0.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.0.msg_type
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.0.enc_part
    }
}

impl FixedTag for KrbPriv {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::KRB_PRIV),
    };
}
