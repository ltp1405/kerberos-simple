use crate::basic::{EncryptedData, KerberosFlags};
use crate::tickets::Ticket;
use der::asn1::ContextSpecific;
use der::Tag::Application;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

#[derive(Sequence, Debug, PartialEq)]
struct KrbApReqInner {
    pvno: ContextSpecific<u8>,
    msg_type: ContextSpecific<u8>,
    ap_options: ContextSpecific<KerberosFlags>,
    ticket: ContextSpecific<Ticket>,
    authenticator: ContextSpecific<EncryptedData>,
}

#[derive(Debug, PartialEq)]
pub struct KrbApReq {
    inner: KrbApReqInner,
}

impl FixedTag for KrbApReq {
    const TAG: Tag = Application {
        number: TagNumber::new(14),
        constructed: true,
    };
}

impl EncodeValue for KrbApReq {
    fn value_len(&self) -> der::Result<Length> {
        self.inner.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.inner.encode(encoder)
    }
}

impl<'a> DecodeValue<'a> for KrbApReq {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let inner = KrbApReqInner::decode(reader)?;
        Ok(Self { inner })
    }
}

impl KrbApReq {
    pub fn new(ap_options: KerberosFlags, ticket: Ticket, authenticator: EncryptedData) -> Self {
        KrbApReq {
            inner: KrbApReqInner {
                pvno: ContextSpecific {
                    value: 5,
                    tag_number: TagNumber::new(0),
                    tag_mode: der::TagMode::Explicit,
                },
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
            },
        }
    }

    pub fn pvno(&self) -> u8 {
        self.inner.pvno.value
    }

    pub fn msg_type(&self) -> u8 {
        self.inner.msg_type.value
    }

    pub fn ap_options(&self) -> &KerberosFlags {
        &self.inner.ap_options.value
    }

    pub fn ticket(&self) -> &Ticket {
        &self.inner.ticket.value
    }

    pub fn authenticator(&self) -> &EncryptedData {
        &self.inner.authenticator.value
    }
}
