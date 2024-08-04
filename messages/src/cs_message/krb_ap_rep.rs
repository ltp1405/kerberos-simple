use crate::basic::EncryptedData;
use der::asn1::ContextSpecific;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Length, Reader, Sequence, TagNumber, Writer,
};

/// KRB_AP_REP message - 5.5.1
#[derive(Debug, PartialEq)]
pub struct KrbApRep(KrbApRepInner);

impl<'a> DecodeValue<'a> for KrbApRep {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let inner = KrbApRepInner::decode(reader)?;
        Ok(Self(inner))
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
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

#[derive(Sequence, Debug, PartialEq)]
struct KrbApRepInner {
    pvno: ContextSpecific<u8>,
    msg_type: ContextSpecific<u8>,
    enc_part: ContextSpecific<EncryptedData>,
}

impl KrbApRep {
    pub fn new(enc_part: EncryptedData) -> Self {
        KrbApRep(KrbApRepInner {
            pvno: ContextSpecific {
                value: 5,
                tag_number: TagNumber::new(0),
                tag_mode: der::TagMode::Explicit,
            },
            msg_type: ContextSpecific {
                value: 15,
                tag_number: TagNumber::new(1),
                tag_mode: der::TagMode::Explicit,
            },
            enc_part: ContextSpecific {
                value: enc_part,
                tag_number: TagNumber::new(2),
                tag_mode: der::TagMode::Explicit,
            },
        })
    }

    pub const fn pvno(&self) -> u8 {
        self.0.pvno.value
    }

    pub const fn msg_type(&self) -> u8 {
        self.0.msg_type.value
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.0.enc_part.value
    }
}
