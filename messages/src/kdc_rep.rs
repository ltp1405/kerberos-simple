use der::Sequence;

use crate::{
    basic::{EncryptedData, Int32, PaData, PrincipalName, Realm, SequenceOf, DEFAULT_LEN},
    tickets::Ticket,
};

#[derive(Sequence)]
pub struct KdcRep {
    #[asn1(context_specific = "0")]
    pvno: Int32,

    #[asn1(context_specific = "1")]
    msg_type: Int32,

    #[asn1(context_specific = "2", optional = "true")]
    padata: Option<SequenceOf<PaData, DEFAULT_LEN>>,

    #[asn1(context_specific = "3")]
    crealm: Realm,

    #[asn1(context_specific = "4")]
    cname: PrincipalName,

    #[asn1(context_specific = "5")]
    ticket: Ticket,

    #[asn1(context_specific = "6")]
    enc_part: EncryptedData,
}

impl KdcRep {
    pub fn new(
        msg_type: Int32,
        padata: Option<SequenceOf<PaData, DEFAULT_LEN>>,
        crealm: Realm,
        cname: PrincipalName,
        ticket: Ticket,
        enc_part: EncryptedData,
    ) -> Self {
        let pvno = Int32::new(b"\x05").expect("Cannot initialize Int32 from &[u8]");
        Self {
            pvno,
            msg_type,
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        }
    }

    pub fn pvno(&self) -> &Int32 {
        &self.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.msg_type
    }

    pub fn padata(&self) -> Option<&SequenceOf<PaData, DEFAULT_LEN>> {
        self.padata.as_ref()
    }

    pub fn crealm(&self) -> &Realm {
        &self.crealm
    }

    pub fn cname(&self) -> &PrincipalName {
        &self.cname
    }

    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.enc_part
    }
}
