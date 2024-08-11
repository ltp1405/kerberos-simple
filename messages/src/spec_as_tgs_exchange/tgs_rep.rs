use der::{FixedTag, Tag, TagNumber};
use std::ops::Deref;

use crate::{
    basic::{application_tags, EncryptedData, PaData, PrincipalName, Realm, SequenceOf},
    spec_as_tgs_exchange::kdc_rep::KdcRep,
    tickets::Ticket,
};

pub struct TgsRep(KdcRep);

impl TgsRep {
    pub fn new(
        padata: impl Into<Option<SequenceOf<PaData>>>,
        crealm: impl Into<Realm>,
        cname: impl Into<PrincipalName>,
        ticket: impl Into<Ticket>,
        enc_part: impl Into<EncryptedData>,
    ) -> Self {
        let msg_type = 13;
        Self(KdcRep::new(
            msg_type, padata, crealm, cname, ticket, enc_part,
        ))
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
