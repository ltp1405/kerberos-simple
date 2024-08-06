use der::Sequence;

use crate::basic::{Int32, KerberosTime, SequenceOf};

#[derive(Sequence)]
pub struct LastReqEntry {
    #[asn1(context_specific = "0")]
    pub lr_type: Int32,

    #[asn1(context_specific = "1")]
    pub lr_value: KerberosTime,
}

impl LastReqEntry {
    pub fn new(lr_type: impl Into<Int32>, lr_value: impl Into<KerberosTime>) -> Self {
        Self {
            lr_type: lr_type.into(),
            lr_value: lr_value.into(),
        }
    }

    pub fn lr_type(&self) -> &Int32 {
        &self.lr_type
    }

    pub fn lr_value(&self) -> &KerberosTime {
        &self.lr_value
    }
}

pub type LastReq = SequenceOf<LastReqEntry>;
