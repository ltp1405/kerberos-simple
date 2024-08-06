use der::{FixedTag, Sequence, Tag, TagNumber};

use crate::basic::{application_tags, EncryptedData, Int32, SequenceOf};
use crate::tickets::Ticket;

#[derive(Sequence)]
pub struct KrbCredInner {
    #[asn1(context_specific = "0")]
    pvno: Int32,

    #[asn1(context_specific = "1")]
    msg_type: Int32,

    #[asn1(context_specific = "2")]
    tickets: SequenceOf<Ticket>,

    #[asn1(context_specific = "3")]
    enc_part: EncryptedData,
}

pub struct KrbCred(KrbCredInner);

impl KrbCred {
    pub fn new(
        pvno: impl Into<Int32>,
        msg_type: impl Into<Int32>,
        tickets: impl Into<SequenceOf<Ticket>>,
        enc_part: impl Into<EncryptedData>,
    ) -> Self {
        let inner = KrbCredInner {
            pvno: pvno.into(),
            msg_type: msg_type.into(),
            tickets: tickets.into(),
            enc_part: enc_part.into(),
        };

        Self(inner)
    }

    pub fn pvno(&self) -> &Int32 {
        &self.0.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.0.msg_type
    }

    pub fn tickets(&self) -> &SequenceOf<Ticket> {
        &self.0.tickets
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.0.enc_part
    }
}

impl FixedTag for KrbCred {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::KRB_CRED),
    };
}