use crate::{
    basic::{application_tags, EncryptedData, Int32, PaData, PrincipalName, Realm, SequenceOf},
    spec_as_tgs_exchange::kdc_rep::KdcRep,
    tickets::Ticket,
};
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, TagNumber,
    Writer,
};
use std::ops::Deref;

#[derive(Eq, PartialEq, Debug)]
pub struct TgsRep(KdcRep);

impl TgsRep {
    pub fn new(
        padata: impl Into<Option<SequenceOf<PaData>>>,
        crealm: impl Into<Realm>,
        cname: impl Into<PrincipalName>,
        ticket: impl Into<Ticket>,
        enc_part: impl Into<EncryptedData>,
    ) -> Self {
        let msg_type = Int32::new(b"\x0D").expect("Cannot initialize Int32 from &[u8]");
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

impl<'a> DecodeValue<'a> for TgsRep {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = KdcRep::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for TgsRep {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for TgsRep {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::TGS_REP),
    };
}

#[cfg(test)]
mod tests {
    use crate::basic::{
        application_tags, ntypes, EncryptedData, Int32, KerberosString, OctetString, PrincipalName,
        Realm,
    };
    use crate::spec_as_tgs_exchange::tgs_rep::TgsRep;
    use crate::tickets::Ticket;
    use der::{Decode, Encode, SliceReader, Tag, TagNumber, Tagged};

    fn sample_data() -> TgsRep {
        TgsRep::new(
            None,
            Realm::new("EXAMPLE.COM").unwrap(),
            PrincipalName::try_from(
                ntypes::NT_PRINCIPAL,
                vec![KerberosString::new("host").unwrap()],
            )
            .unwrap(),
            Ticket::new(
                Realm::new("EXAMPLE.COM").unwrap(),
                PrincipalName::try_from(
                    ntypes::NT_PRINCIPAL,
                    vec![KerberosString::new("krbtgt").unwrap()],
                )
                .unwrap(),
                EncryptedData::new(
                    Int32::new(b"\x01").unwrap(),
                    Int32::new(b"\x0A").unwrap(),
                    OctetString::new(b"abc").unwrap(),
                ),
            ),
            EncryptedData::new(
                Int32::new(b"\x02").unwrap(),
                Int32::new(b"\x0B").unwrap(),
                OctetString::new(b"xyz").unwrap(),
            ),
        )
    }

    #[test]
    fn test_primitives() {
        let data = sample_data();
        assert_eq!(*data.pvno(), Int32::new(b"\x05").unwrap());
        assert_eq!(*data.msg_type(), Int32::new(b"\x0B").unwrap());
        assert!(data.padata().is_none());
    }

    #[test]
    fn test_tag() {
        let data = sample_data();
        let tag = Tag::Application {
            constructed: true,
            number: TagNumber::new(application_tags::TGS_REP),
        };
        assert_eq!(data.tag(), tag);
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded_data: TgsRep =
            TgsRep::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded_data, data);
    }
}
