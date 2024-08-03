use der::{FixedTag, Tag, TagNumber};

use crate::{
    basic::{EncryptedData, Int32, PaData, PrincipalName, Realm, SequenceOf},
    spec_as_tgs_exchange::kdc_rep::KdcRep,
    tickets::Ticket,
};

pub struct TgsRep {
    inner: KdcRep,
}

impl TgsRep {
    pub fn new(
        padata: Option<SequenceOf<PaData>>,
        crealm: Realm,
        cname: PrincipalName,
        ticket: Ticket,
        enc_part: EncryptedData,
    ) -> Self {
        let msg_type = Int32::new(b"\x0D").expect("Cannot initialize Int32 from &[u8]");
        let inner = KdcRep::new(msg_type, padata, crealm, cname, ticket, enc_part);
        Self { inner }
    }

    pub fn inner(&self) -> &KdcRep {
        &self.inner
    }
}

impl FixedTag for TgsRep {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(13),
    };
}
