use der::{Decode, DecodeValue, Encode, EncodeValue, FixedTag, Sequence, TagNumber};

use crate::basic::{
    application_tags, EncryptedData, Int32, KerberosFlags, KerberosString, PrincipalName, Realm,
};

mod enc_ticket_part;
mod transited_encoding;

pub use enc_ticket_part::{EncTicketPart, EncTicketPartBuilder, EncTicketPartInner};
pub use transited_encoding::TransitedEncoding;

// RFC 4120 Section 5.3
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Ticket(TicketInner);

impl Ticket {
    pub fn new(realm: Realm, sname: PrincipalName, enc_part: EncryptedData) -> Self {
        Self(TicketInner::new(realm, sname, enc_part))
    }
}

impl AsRef<TicketInner> for Ticket {
    fn as_ref(&self) -> &TicketInner {
        &self.0
    }
}

impl EncodeValue for Ticket {
    fn value_len(&self) -> der::Result<der::Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode(encoder)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for Ticket {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let inner = TicketInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl FixedTag for Ticket {
    const TAG: der::Tag = der::Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::TICKET),
    };
}

#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct TicketInner {
    #[asn1(context_specific = "0")]
    tkt_vno: Int32,
    #[asn1(context_specific = "1")]
    realm: Realm,
    #[asn1(context_specific = "2")]
    sname: PrincipalName,
    #[asn1(context_specific = "3")]
    enc_part: EncryptedData,
}

impl TicketInner {
    fn new(realm: Realm, sname: PrincipalName, enc_part: EncryptedData) -> Self {
        let tkt_vno = 5;
        Self {
            tkt_vno,
            realm,
            sname,
            enc_part,
        }
    }

    pub fn tkt_vno(&self) -> &Int32 {
        &self.tkt_vno
    }

    pub fn realm(&self) -> &KerberosString {
        &self.realm
    }

    pub fn sname(&self) -> &PrincipalName {
        &self.sname
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.enc_part
    }
}

pub type TicketFlags = KerberosFlags;

#[cfg(test)]
mod test;
