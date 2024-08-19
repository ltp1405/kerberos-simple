use crate::basic::{EncryptionKey, KerberosTime, Microseconds, UInt32};
use der::Tag::Application;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

#[derive(Sequence, Debug, PartialEq, Clone)]
struct EncApRepPartInner {
    #[asn1(context_specific = "0")]
    ctime: KerberosTime,

    #[asn1(context_specific = "1")]
    cusec: Microseconds,

    #[asn1(context_specific = "2", optional = "true")]
    subkey: Option<EncryptionKey>,

    #[asn1(context_specific = "3", optional = "true")]
    seq_number: Option<UInt32>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct EncApRepPart(EncApRepPartInner);

impl<'a> DecodeValue<'a> for EncApRepPart {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = EncApRepPartInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl FixedTag for EncApRepPart {
    const TAG: Tag = Application {
        number: TagNumber::new(27),
        constructed: true,
    };
}

impl EncodeValue for EncApRepPart {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl EncApRepPart {
    pub fn new(
        ctime: impl Into<KerberosTime>,
        cusec: impl Into<Microseconds>,
        subkey: Option<impl Into<EncryptionKey>>,
        seq_number: Option<impl Into<UInt32>>,
    ) -> Self {
        EncApRepPart(EncApRepPartInner {
            ctime: ctime.into(),
            cusec: cusec.into(),
            subkey: subkey.map(|subkey| subkey.into()),
            seq_number: seq_number.map(|seq_number| seq_number.into()),
        })
    }

    pub fn ctime(&self) -> &KerberosTime {
        &self.0.ctime
    }

    pub fn cusec(&self) -> &Microseconds {
        &self.0.cusec
    }

    pub fn seq_number(&self) -> Option<&UInt32> {
        self.0.seq_number.as_ref().map(|seq_number| seq_number)
    }

    pub fn subkey(&self) -> Option<&EncryptionKey> {
        self.0.subkey.as_ref().map(|subkey| subkey)
    }
}

#[cfg(test)]
mod tests {
    use crate::basic::{EncryptionKey, KerberosTime, OctetString};
    use crate::cs_message::EncApRepPart;
    use der::{Decode, Encode};
    use std::ops::Add;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn encode_and_decode() {
        let msg = EncApRepPart::new(
            KerberosTime::from_system_time(SystemTime::now()).unwrap(),
            564,
            None::<EncryptionKey>,
            Some(2),
        );
        let encoded = msg.to_der().unwrap();
        let decoded = EncApRepPart::from_der(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn correct_encoding() {
        let msg = EncApRepPart::new(
            KerberosTime::from_system_time(UNIX_EPOCH.add(Duration::from_secs(10000))).unwrap(),
            1000,
            None::<EncryptionKey>,
            Some(2),
        );
        #[rustfmt::skip]
        let expected_encoding = vec![
            0b0110_0000u8 + 27, 32, 48, 30, // APPLICATION 27
                160, 17, 24, 15, // ctime [0] KerberosTime
                    49, 57, 55, 48, 48, 49, 48, 49, 48, 50, 52, 54, 52, 48, 90,
                161, 4, 2, 2, 3, 232, // cusec [1] Microseconds
                163, 3, 2, 1, 2 // seq-number [3] UInt32 OPTIONAL
        ];
        assert_eq!(expected_encoding, msg.to_der().unwrap());

        let msg = EncApRepPart::new(
            KerberosTime::from_system_time(UNIX_EPOCH.add(Duration::from_secs(10000))).unwrap(),
            1000,
            Some(EncryptionKey::new(1, OctetString::new(&[1, 2, 3]).unwrap())),
            Some(2),
        );
        println!("{:?}", msg.to_der().unwrap());

        #[rustfmt::skip]
        let expected_encoding = vec![
            0b0110_0000u8 + 27, 48, 48, 46, // APPLICATION 27
                160, 17, 24, 15, // ctime [0] KerberosTime
                    49, 57, 55, 48, 48, 49, 48, 49, 48, 50, 52, 54, 52, 48, 90,
                161, 4, 2, 2, 3, 232, // cusec [1] Microseconds
                162, 14, 48, 12, // subkey [2] EncryptionKey OPTIONAL
                    160, 3, 2, 1, 1,
                    161, 5, 4, 3, 1, 2, 3,
                163, 3, 2, 1, 2 // seq-number [3] UInt32 OPTIONAL
        ];
        assert_eq!(expected_encoding, msg.to_der().unwrap());
    }
}
