use crate::{
    basic::{application_tags, EncryptedData, PaData, PrincipalName, Realm, SequenceOf},
    spec_as_tgs_exchange::kdc_rep::KdcRep,
    tickets::Ticket,
};
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, TagNumber,
    Writer,
};
use std::ops::Deref;

#[derive(Eq, PartialEq, Debug, Clone)]
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
            msg_type, padata.into(), crealm, cname, ticket, enc_part,
        ))
    }
}

impl Deref for AsRep {
    type Target = KdcRep;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DecodeValue<'a> for AsRep {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = KdcRep::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for AsRep {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for AsRep {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::AS_REP),
    };
}

#[cfg(test)]
mod tests {
    use crate::basic::{
        application_tags, EncryptedData, KerberosString, NameTypes, OctetString, PrincipalName,
        Realm,
    };
    use crate::spec_as_tgs_exchange::as_rep::AsRep;
    use crate::tickets::Ticket;
    use der::{Decode, Encode, SliceReader, Tag, TagNumber, Tagged};

    fn sample_data() -> AsRep {
        AsRep::new(
            None,
            Realm::new("EXAMPLE.COM").unwrap(),
            PrincipalName::new(
                NameTypes::NtPrincipal,
                vec![KerberosString::new("host").unwrap()],
            )
            .unwrap(),
            Ticket::new(
                Realm::new("EXAMPLE.COM").unwrap(),
                PrincipalName::new(
                    NameTypes::NtPrincipal,
                    vec![KerberosString::new("krbtgt").unwrap()],
                )
                .unwrap(),
                EncryptedData::new(1, 10, OctetString::new(b"abc").unwrap()),
            ),
            EncryptedData::new(2, 11, OctetString::new(b"xyz").unwrap()),
        )
    }

    #[test]
    fn test_primitives() {
        let data = sample_data();
        assert_eq!(*data.pvno(), 5);
        assert_eq!(*data.msg_type(), 11);
        assert!(data.padata().is_none());
    }

    #[test]
    fn test_tag() {
        let data = sample_data();
        let tag = Tag::Application {
            constructed: true,
            number: TagNumber::new(application_tags::AS_REP),
        };
        assert_eq!(data.tag(), tag);
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded_data: AsRep =
            AsRep::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded_data, data);
    }
}
