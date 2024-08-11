use der::{FixedTag, Tag, TagNumber};
use std::ops::Deref;

use crate::{
    basic::{application_tags, EncryptedData, Int32, PaData, PrincipalName, Realm, SequenceOf},
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
        let msg_type = 11;
        Self(KdcRep::new(
            msg_type, padata, crealm, cname, ticket, enc_part,
        ))
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
