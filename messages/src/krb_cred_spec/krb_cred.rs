use der::{FixedTag, Sequence, Tag, TagNumber};

use crate::basic::{application_tags, EncryptedData, Int32, SequenceOf};
use crate::tickets::Ticket;

#[derive(Sequence)]
pub struct KrbCredInner {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pvno: Int32,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    msg_type: Int32,

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    tickets: SequenceOf<Ticket>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
    enc_part: EncryptedData,
}

pub struct KrbCred {
    inner: KrbCredInner,
}

impl KrbCred {
    pub fn new(pvno: Int32, msg_type: Int32, tickets: SequenceOf<Ticket>, enc_part: EncryptedData) -> Self {
        let inner = KrbCredInner {
            pvno,
            msg_type,
            tickets,
            enc_part,
        };

        Self { inner }
    }

    pub fn pvno(&self) -> &Int32 {
        &self.inner.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.inner.msg_type
    }

    pub fn tickets(&self) -> &SequenceOf<Ticket> {
        &self.inner.tickets
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.inner.enc_part
    }
}

impl FixedTag for KrbCred {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::KRB_CRED),
    };
}