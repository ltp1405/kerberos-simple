use crate::{
    basic::{EncryptedData, Int32, PaData, PrincipalName, Realm, SequenceOf},
    tickets::Ticket,
};
use der::Sequence;

#[derive(Sequence, Eq, PartialEq, Debug)]
pub struct KdcRep {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pvno: Int32,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    msg_type: Int32,

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    padata: Option<SequenceOf<PaData>>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
    crealm: Realm,

    #[asn1(context_specific = "4", tag_mode = "EXPLICIT")]
    cname: PrincipalName,

    #[asn1(context_specific = "5", tag_mode = "EXPLICIT")]
    ticket: Ticket,

    #[asn1(context_specific = "6", tag_mode = "EXPLICIT")]
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
        let pvno = Int32::new(b"\x05").expect("Cannot initialize Int32 from &[u8]");
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

#[cfg(test)]
pub mod tests {
    use crate::basic::{
        ntypes, EncryptedData, Int32, KerberosString, OctetString, PrincipalName, Realm,
    };
    use crate::spec_as_tgs_exchange::kdc_rep::KdcRep;
    use crate::tickets::Ticket;
    use der::{Decode, Encode, SliceReader};

    fn sample_data() -> KdcRep {
        KdcRep::new(
            Int32::new(b"\x01").unwrap(),
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
        assert_eq!(data.pvno(), &Int32::new(b"\x05").unwrap());
        assert_eq!(data.msg_type(), &Int32::new(b"\x01").unwrap());
        assert!(data.padata().is_none());
        assert_eq!(data.crealm(), &Realm::new("EXAMPLE.COM").unwrap());
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded_data: KdcRep =
            KdcRep::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(decoded_data, data);
    }
}
