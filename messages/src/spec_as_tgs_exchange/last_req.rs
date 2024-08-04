use der::Sequence;

use crate::basic::{Int32, KerberosTime, SequenceOf};

#[derive(Sequence)]
pub struct LastReqEntry {
    #[asn1(context_specific = "0", tag_mode= "EXPLICIT")]
    pub lr_type: Int32,

    #[asn1(context_specific = "1", tag_mode= "EXPLICIT")]
    pub lr_value: KerberosTime,
}

pub type LastReq = SequenceOf<LastReqEntry>;
