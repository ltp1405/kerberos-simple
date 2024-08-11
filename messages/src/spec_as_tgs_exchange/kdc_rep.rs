use der::Sequence;

use crate::{
    basic::{EncryptedData, Int32, PaData, PrincipalName, Realm, SequenceOf},
    tickets::Ticket,
};

#[derive(Sequence)]
pub struct KdcRep {
    #[asn1(context_specific = "0", tag_mode= "EXPLICIT")]
    pvno: Int32,

    #[asn1(context_specific = "1", tag_mode= "EXPLICIT")]
    msg_type: Int32,

    #[asn1(context_specific = "2", tag_mode= "EXPLICIT", optional = "true")]
    padata: Option<SequenceOf<PaData>>,

    #[asn1(context_specific = "3", tag_mode= "EXPLICIT")]
    crealm: Realm,

    #[asn1(context_specific = "4", tag_mode= "EXPLICIT")]
    cname: PrincipalName,

    #[asn1(context_specific = "5", tag_mode= "EXPLICIT")]
    ticket: Ticket,

    #[asn1(context_specific = "6", tag_mode= "EXPLICIT")]
    enc_part: EncryptedData,
}

impl KdcRep {
    pub fn new(
        msg_type: impl Into<Int32>,
        padata: impl Into<Option<SequenceOf<PaData>>>,
        crealm: impl Into<Realm>,
        cname: impl Into<PrincipalName>,
        ticket: impl Into<Ticket>,
        enc_part: impl Into<EncryptedData>,
    ) -> Self {
        let pvno = 5;
        Self {
            pvno,
            msg_type: msg_type.into(),
            padata: padata.into(),
            crealm: crealm.into(),
            cname: cname.into(),
            ticket: ticket.into(),
            enc_part: enc_part.into(),
        }
    }

    pub fn pvno(&self) -> &Int32 {
        &self.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.msg_type
    }

    pub fn padata(&self) -> Option<&SequenceOf<PaData>> {
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
