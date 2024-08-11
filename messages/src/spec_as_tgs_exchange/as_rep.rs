use std::ops::Deref;
use der::{FixedTag, Tag, TagNumber};

use crate::{
    basic::{EncryptedData, Int32, PaData, PrincipalName, Realm, SequenceOf, application_tags},
    spec_as_tgs_exchange::kdc_rep::KdcRep,
    tickets::Ticket,
};

pub struct AsRep(KdcRep);

impl AsRep {
    pub fn new(
        padata: impl Into<Option<SequenceOf<PaData>>>,
        crealm: impl Into<Realm>,
        cname: impl Into<PrincipalName>,
        ticket: impl Into<Ticket>,
        enc_part: impl Into<EncryptedData>,
    ) -> Self {
        let msg_type = Int32::new(b"\x0B").expect("Cannot initialize Int32 from &[u8]");
        Self(KdcRep::new(msg_type, padata, crealm, cname, ticket, enc_part))
    }
}

impl Deref for AsRep {
    type Target = KdcRep;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FixedTag for AsRep {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::AS_REP),
    };
}