use der::Sequence;

use crate::basic::EncryptedData;
use crate::basic::Int32;

#[derive(Sequence)]
// Missing Application tag
pub struct KrbPriv {
    #[asn1(context_specific = "0")]
    pvno: Int32,

    #[asn1(context_specific = "1")]
    msg_type: Int32,

    #[asn1(context_specific = "3")]
    enc_part: EncryptedData,
}

impl KrbPriv {
    pub fn new(pvno: Int32, msg_type: Int32, enc_part: EncryptedData) -> Self {
        Self {
            pvno,
            msg_type,
            enc_part,
        }
    }

    pub fn pvno(&self) -> &Int32 {
        &self.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.msg_type
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.enc_part
    }
}

// impl FixedTag for KrbPriv {
//     const TAG: Tag = Tag::Application {
//         constructed: true,
//         number: TagNumber::new(21),
//     };
// }
