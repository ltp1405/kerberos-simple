use std::ops::Deref;
use der::{FixedTag, Tag, TagNumber};

use crate::{
    basic::{EncryptedData, Int32, PaData, PrincipalName, Realm, SequenceOf, application_tags},
    spec_as_tgs_exchange::kdc_rep::KdcRep,
    tickets::Ticket,
};

pub struct TgsRep(KdcRep);

impl TgsRep {
    pub fn new(
        padata: Option<SequenceOf<PaData>>,
        crealm: Realm,
        cname: PrincipalName,
        ticket: Ticket,
        enc_part: EncryptedData,
    ) -> Self {
        let msg_type = Int32::new(b"\x0D").expect("Cannot initialize Int32 from &[u8]");
        Self(KdcRep::new(msg_type, padata, crealm, cname, ticket, enc_part))
    }
}

impl Deref for TgsRep {
    type Target = KdcRep;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FixedTag for TgsRep {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::TGS_REP),
    };
}
