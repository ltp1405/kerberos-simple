use der::asn1::ContextSpecific;
use der::{Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag, Tagged, TagNumber, Writer};
use der::Tag::Application;
use crate::basic::{EncryptedData, KerberosFlags};

#[derive(Sequence, Debug, PartialEq)]
struct KrbApReqInner {
    pvno: ContextSpecific<u8>,
    msg_type: ContextSpecific<u8>,

    // TODO: Wait for APOptions to be Sequence
    // ap_options: ContextSpecific<KerberosFlags>,

    // TODO: Wait for Ticket
    // ticket: ContextSpecific<Ticket>,

    // TODO: Wait for EncryptedData to be Sequence
    // authenticator: ContextSpecific<EncryptedData>,
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
    pub fn new(ap_options: KerberosFlags, authenticator: EncryptedData) -> Self {
        KrbApReq {
            inner: KrbApReqInner {
                pvno: ContextSpecific { value: 5, tag_number: TagNumber::new(0), tag_mode: der::TagMode::Explicit },
                msg_type: ContextSpecific { value: 14, tag_number: TagNumber::new(1), tag_mode: der::TagMode::Explicit },
                // ap_options: ContextSpecific { value: ap_options, tag_number: TagNumber::new(2), tag_mode: der::TagMode::Explicit },
                // authenticator: ContextSpecific { value: authenticator, tag_number: TagNumber::new(3), tag_mode: der::TagMode::Explicit },
            }
        }
    }

    pub fn pvno(&self) -> u8 {
        self.inner.pvno.value
    }

    pub fn msg_type(&self) -> u8 {
        self.inner.msg_type.value
    }

    pub fn ap_options(&self) -> &KerberosFlags {
        todo!("Wait for APOptions to be Sequence")
        // &self.inner.ap_options.value
    }

    pub fn authenticator(&self) -> &EncryptedData {
        todo!("Wait for EncryptedData to be Sequence")
        // &self.inner.authenticator.value
    }
}

#[cfg(test)]
mod tests {
    use der::asn1::BitString;
    use der::Decode;
    use super::*;

    #[test]
    fn encode_and_decode() {
        let krb_ap_req = KrbApReq::new(KerberosFlags {
            flags: BitString::from_bytes(&[1, 2]).unwrap(),
        }, EncryptedData {
            i: 2,
        });
        let mut v = Vec::new();
        krb_ap_req.encode_to_vec(&mut v).unwrap();
        println!("{:x?}", v);
        let mut v2 = Vec::new();
        krb_ap_req.inner.encode_to_vec(&mut v2).unwrap();
        println!("{:x?}", v2);

        assert_ne!(v, v2, "KrbApReq should be constructed and explicitly tagged");

        let krb_ap_req2 = KrbApReq::from_der(&v).unwrap();
        assert_eq!(krb_ap_req, krb_ap_req2);
    }
}