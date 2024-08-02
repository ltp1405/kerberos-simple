use der::{FixedTag, Tag, TagNumber};

use crate::{
    basic::{EncryptedData, Int32, PaData, PrincipalName, Realm, SequenceOf, DEFAULT_LEN},
    kdc_rep::KdcRep,
    tickets::Ticket,
};

pub struct AsRep {
    inner: KdcRep,
}

impl AsRep {
    pub fn new(
        padata: Option<SequenceOf<PaData, DEFAULT_LEN>>,
        crealm: Realm,
        cname: PrincipalName,
        ticket: Ticket,
        enc_part: EncryptedData,
    ) -> Self {
        let msg_type = Int32::new(b"\x0B").expect("Cannot initialize Int32 from &[u8]");
        let inner = KdcRep::new(msg_type, padata, crealm, cname, ticket, enc_part);
        Self { inner }
    }

    pub fn inner(&self) -> &KdcRep {
        &self.inner
    }
}

impl FixedTag for AsRep {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(11),
    };
}
