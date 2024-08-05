use crate::basic::{BitSring, EncryptedData, KerberosFlags};
use crate::tickets::Ticket;
use der::asn1::{BitString, ContextSpecific};
use der::Tag::Application;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

// TODO: Should replace BitString with KerberosFlags when it is correctly implemented
#[derive(Debug, PartialEq, Clone)]
struct APOptions(BitString);

enum APOptionFlag {
    UseSessionKey = 0b0100_0000,
    MutualRequired = 0b0010_0000,
}

impl APOptions {
    fn new(use_session_key: bool, mutual_required: bool) -> Self {
        let mut buf = [0x0_u8; 4];
        if use_session_key {
            buf[0] |= APOptionFlag::UseSessionKey as u8;
        }
        if mutual_required {
            buf[0] |= APOptionFlag::MutualRequired as u8;
        }
        Self(BitString::new(0, buf.to_vec()).unwrap())
    }

    fn use_session_key(&self) -> bool {
        self.0.as_bytes().unwrap()[0] & APOptionFlag::UseSessionKey as u8 != 0
    }

    fn mutual_required(&self) -> bool {
        self.0.as_bytes().unwrap()[0] & APOptionFlag::MutualRequired as u8 != 0
    }
}

impl FixedTag for APOptions {
    const TAG: Tag = Tag::BitString;
}

impl EncodeValue for APOptions {
    fn value_len(&self) -> der::Result<Length> {
        self.0.value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode_value(encoder)
    }
}

impl<'a> DecodeValue<'a> for APOptions {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let inner = BitString::decode_value(reader, header)?;
        Ok(Self(inner))
    }
}

#[derive(Sequence, Debug, PartialEq)]
struct KrbApReqInner {
    pvno: ContextSpecific<u8>,
    msg_type: ContextSpecific<u8>,
    ap_options: ContextSpecific<APOptions>,
    ticket: ContextSpecific<Ticket>,
    authenticator: ContextSpecific<EncryptedData>,
}

#[derive(Debug, PartialEq)]
pub struct KrbApReq(KrbApReqInner);

impl FixedTag for KrbApReq {
    const TAG: Tag = Application {
        number: TagNumber::new(14),
        constructed: true,
    };
}

impl EncodeValue for KrbApReq {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> DecodeValue<'a> for KrbApReq {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = KrbApReqInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl KrbApReq {
    pub fn new(ap_options: APOptions, ticket: Ticket, authenticator: EncryptedData) -> Self {
        fn make_tag<T>(value: T, number: u8) -> ContextSpecific<T> {
            ContextSpecific {
                value,
                tag_number: TagNumber::new(number),
                tag_mode: der::TagMode::Explicit,
            }
        }
        KrbApReq(KrbApReqInner {
            pvno: make_tag(5, 0),
            msg_type: ContextSpecific {
                value: 14,
                tag_number: TagNumber::new(1),
                tag_mode: der::TagMode::Explicit,
            },
            ap_options: ContextSpecific {
                value: ap_options,
                tag_number: TagNumber::new(2),
                tag_mode: der::TagMode::Explicit,
            },
            ticket: ContextSpecific {
                value: ticket,
                tag_number: TagNumber::new(3),
                tag_mode: der::TagMode::Explicit,
            },
            authenticator: ContextSpecific {
                value: authenticator,
                tag_number: TagNumber::new(4),
                tag_mode: der::TagMode::Explicit,
            },
        })
    }

    pub fn pvno(&self) -> u8 {
        self.0.pvno.value
    }

    pub fn msg_type(&self) -> u8 {
        self.0.msg_type.value
    }

    pub fn ap_options(&self) -> &APOptions {
        &self.0.ap_options.value
    }

    pub fn ticket(&self) -> &Ticket {
        &self.0.ticket.value
    }

    pub fn authenticator(&self) -> &EncryptedData {
        &self.0.authenticator.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ap_option_correct_flag_encoding() {
        let ap_options = APOptions::new(true, true);
        assert_eq!(ap_options.use_session_key(), true);
        assert_eq!(ap_options.mutual_required(), true);

        let buf = ap_options.to_der().expect("Cannot encode APOptions");
        assert_eq!(buf, [0x03, 5, 0, 0b0110_0000, 0x0, 0x0, 0x0]);

        let ap_options = APOptions::new(false, true);
        assert_eq!(ap_options.use_session_key(), false);
        assert_eq!(ap_options.mutual_required(), true);
        let buf = ap_options.to_der().expect("Cannot encode APOptions");
        assert_eq!(buf, [0x03, 5, 0, 0b0010_0000, 0x0, 0x0, 0x0]);

        let ap_options = APOptions::new(true, false);
        assert_eq!(ap_options.use_session_key(), true);
        assert_eq!(ap_options.mutual_required(), false);
        let buf = ap_options.to_der().expect("Cannot encode APOptions");
        assert_eq!(buf, [0x03, 5, 0, 0b0100_0000, 0x0, 0x0, 0x0]);
    }

    fn req_correct_header() {
        let ap_options = APOptions::new(true, true);
    }
}
