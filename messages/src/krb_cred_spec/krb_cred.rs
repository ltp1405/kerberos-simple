use der::Sequence;

use crate::basic::{EncryptedData, Int32, SequenceOf};
use crate::tickets::Ticket;

#[derive(Sequence)]
pub struct KrbCred {
    #[asn1(context_specific = "0")]
    pvno: Int32,

    #[asn1(context_specific = "1")]
    msg_type: Int32,

    #[asn1(context_specific = "2")]
    tickets: SequenceOf<Ticket>,

    #[asn1(context_specific = "3")]
    enc_part: EncryptedData,
}

impl KrbCred {
    pub fn new(pvno: Int32, msg_type: Int32, tickets: SequenceOf<Ticket>, enc_part: EncryptedData) -> Self {
        Self {
            pvno,
            msg_type,
            tickets,
            enc_part,
        }
    }

    pub fn pvno(&self) -> &Int32 {
        &self.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.msg_type
    }

    pub fn tickets(&self) -> &SequenceOf<Ticket> {
        &self.tickets
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.enc_part
    }
}