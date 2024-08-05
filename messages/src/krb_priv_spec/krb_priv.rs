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
    pub fn new(
        pvno: impl Into<Int32>,
        msg_type: impl Into<Int32>,
        enc_part: impl Into<EncryptedData>,
    ) -> Self {
        Self(KrbPrivInner {
            pvno: pvno.into(),
            msg_type: msg_type.into(),
            enc_part: enc_part.into(),
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
