use der::asn1::ContextSpecific;
use der::{Decode, DecodeValue, Encode, EncodeValue, FixedTag, Length, Reader, Sequence, TagNumber, Writer};
use crate::basic::EncryptedData;

/// KRB_AP_REP message - 5.5.1
#[derive(Debug, PartialEq)]
pub struct KrbApRep {
    inner: KrbApRepInner,
}

impl<'a> DecodeValue<'a> for KrbApRep {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let inner = KrbApRepInner::decode(reader)?;
        Ok(Self { inner })
    }
}

impl FixedTag for KrbApRep {
    const TAG: der::Tag = der::Tag::Application {
        number: TagNumber::new(15),
        constructed: true,
    };
}

impl EncodeValue for KrbApRep {
    fn value_len(&self) -> der::Result<Length> {
        self.inner.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.inner.encode(encoder)
    }
}

#[derive(Sequence, Debug, PartialEq)]
struct KrbApRepInner {
    pvno: ContextSpecific<u8>,
    msg_type: ContextSpecific<u8>,
    // TODO: Wait for EncryptedData to be Sequence
    // enc_part: ContextSpecific<EncryptedData>,
}

impl KrbApRep {
    pub fn new(enc_part: EncryptedData) -> Self {
        KrbApRep {
            inner: KrbApRepInner {
                pvno: ContextSpecific { value: 5, tag_number: TagNumber::new(0), tag_mode: der::TagMode::Explicit },
                msg_type: ContextSpecific { value: 15, tag_number: TagNumber::new(1), tag_mode: der::TagMode::Explicit },
                // enc_part: ContextSpecific { value: enc_part, tag_number: TagNumber::new(2), tag_mode: der::TagMode::Explicit },
            }
        }
    }

    pub fn pvno(&self) -> u8 {
        self.inner.pvno.value
    }

    pub fn msg_type(&self) -> u8 {
        self.inner.msg_type.value
    }

    pub fn enc_part(&self) -> &EncryptedData {
        todo!("Wait for EncryptedData to be Sequence")
        // &self.inner.enc_part.value
    }
}