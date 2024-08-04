use crate::basic::{EncryptionKey, KerberosTime, Microseconds, UInt32};
use der::asn1::ContextSpecific;
use der::Tag::Application;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

#[derive(Sequence, Debug)]
pub struct EncApRepPartInner {
    ctime: ContextSpecific<KerberosTime>,
    cusec: ContextSpecific<Microseconds>,
    subkey: Option<ContextSpecific<EncryptionKey>>,
    seq_number: Option<ContextSpecific<UInt32>>,
}

struct EncApRepPart {
    inner: EncApRepPartInner,
}

impl<'a> DecodeValue<'a> for EncApRepPart {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let inner = EncApRepPartInner::decode(reader)?;
        Ok(Self { inner })
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
        self.inner.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        todo!()
    }
}

impl EncApRepPart {
    pub fn new(
        ctime: impl Into<KerberosTime>,
        cusec: impl Into<Microseconds>,
        subkey: Option<EncryptionKey>,
        seq_number: Option<impl Into<UInt32>>,
    ) -> Self {
        EncApRepPart {
            inner: EncApRepPartInner {
                ctime: ContextSpecific {
                    value: ctime.into(),
                    tag_number: TagNumber::new(0),
                    tag_mode: der::TagMode::Explicit,
                },
                cusec: ContextSpecific {
                    value: cusec.into(),
                    tag_number: TagNumber::new(1),
                    tag_mode: der::TagMode::Explicit,
                },
                subkey: subkey.map(|subkey| ContextSpecific {
                    value: subkey,
                    tag_number: TagNumber::new(2),
                    tag_mode: der::TagMode::Explicit,
                }),
                seq_number: seq_number.map(|seq_number| ContextSpecific {
                    value: seq_number.into(),
                    tag_number: TagNumber::new(3),
                    tag_mode: der::TagMode::Explicit,
                }),
            },
        }
    }

    pub fn ctime(&self) -> KerberosTime {
        self.inner.ctime.value
    }

    pub fn cusec(&self) -> Microseconds {
        todo!("Wait for Microseconds to be ready")
        // self.inner.cusec.value
    }

    pub fn seq_number(&self) -> Option<UInt32> {
        self.inner
            .seq_number
            .as_ref()
            .map(|seq_number| seq_number.value.to_owned())
    }

    pub fn subkey(&self) -> Option<EncryptionKey> {
        self.inner
            .subkey
            .as_ref()
            .map(|subkey| subkey.value.to_owned())
    }
}
