use crate::basic::{EncryptionKey, KerberosTime, Microseconds, UInt32};
use der::asn1::ContextSpecific;
use der::Tag::Application;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

#[derive(Sequence, Debug, PartialEq, Clone)]
pub struct EncApRepPartInner {
    ctime: ContextSpecific<KerberosTime>,
    cusec: ContextSpecific<Microseconds>,
    subkey: Option<ContextSpecific<EncryptionKey>>,
    seq_number: Option<ContextSpecific<UInt32>>,
}

#[derive(Debug, PartialEq, Clone)]
struct EncApRepPart(EncApRepPartInner);

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
        self.0.ctime.encode(encoder)?;
        self.0.cusec.encode(encoder)?;
        self.0.subkey.encode(encoder)?;
        self.0.seq_number.encode(encoder)
    }
}

impl EncApRepPart {
    pub fn new(
        ctime: impl Into<KerberosTime>,
        cusec: impl Into<Microseconds>,
        subkey: Option<impl Into<EncryptionKey>>,
        seq_number: Option<impl Into<UInt32>>,
    ) -> Self {
        fn make_tag<T>(value: T, number: u8) -> ContextSpecific<T> {
            ContextSpecific {
                value,
                tag_number: TagNumber::new(number),
                tag_mode: der::TagMode::Explicit,
            }
        }
        EncApRepPart(EncApRepPartInner {
            ctime: make_tag(ctime.into(), 0),
            cusec: make_tag(cusec.into(), 1),
            subkey: subkey.map(|subkey| make_tag(subkey.into(), 2)),
            seq_number: seq_number.map(|seq_number| make_tag(seq_number.into(), 3)),
        })
    }

    pub fn ctime(&self) -> KerberosTime {
        self.0.ctime.value
    }

    pub fn cusec(&self) -> Microseconds {
        todo!("Wait for Microseconds to be ready")
        // self.0.cusec.value
    }

    pub fn seq_number(&self) -> Option<UInt32> {
        self.0
            .seq_number
            .as_ref()
            .map(|seq_number| seq_number.value.to_owned())
    }

    pub fn subkey(&self) -> Option<EncryptionKey> {
        self.0.subkey.as_ref().map(|subkey| subkey.value.to_owned())
    }
}
