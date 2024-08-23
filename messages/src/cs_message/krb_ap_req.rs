use der::Tag::Application;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};

use crate::basic::{EncryptedData, KerberosFlags};
use crate::tickets::Ticket;

#[derive(Debug, PartialEq, Clone)]
pub struct APOptions(KerberosFlags);

enum APOptionFlag {
    UseSessionKey = 1,
    MutualRequired = 2,
}

impl APOptions {
    pub fn new(use_session_key: bool, mutual_required: bool) -> Self {
        let mut flags_builder = KerberosFlags::builder();
        if use_session_key {
            flags_builder.set(APOptionFlag::UseSessionKey as usize);
        }

        if mutual_required {
            flags_builder.set(APOptionFlag::MutualRequired as usize);
        }
        Self(flags_builder.build().expect("This should not failed"))
    }

    pub fn use_session_key(&self) -> bool {
        self.0.is_set(APOptionFlag::UseSessionKey as usize)
    }

    pub fn mutual_required(&self) -> bool {
        self.0.is_set(APOptionFlag::MutualRequired as usize)
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
        let inner = KerberosFlags::decode_value(reader, header)?;
        Ok(Self(inner))
    }
}

#[derive(Sequence, Debug, PartialEq, Clone)]
struct KrbApReqInner {
    #[asn1(context_specific = "0")]
    pvno: u8,

    #[asn1(context_specific = "1")]
    msg_type: u8,

    #[asn1(context_specific = "2")]
    ap_options: APOptions,

    #[asn1(context_specific = "3")]
    ticket: Ticket,

    #[asn1(context_specific = "4")]
    authenticator: EncryptedData,
}

#[derive(Debug, PartialEq, Clone)]
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
        KrbApReq(KrbApReqInner {
            pvno: 5,
            msg_type: 14,
            ap_options,
            ticket,
            authenticator,
        })
    }

    pub fn pvno(&self) -> &u8 {
        &self.0.pvno
    }

    pub fn msg_type(&self) -> &u8 {
        &self.0.msg_type
    }

    pub fn ap_options(&self) -> &APOptions {
        &self.0.ap_options
    }

    pub fn ticket(&self) -> &Ticket {
        &self.0.ticket
    }

    pub fn authenticator(&self) -> &EncryptedData {
        &self.0.authenticator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basic::{KerberosString, NameTypes, OctetString, PrincipalName, Realm};

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

    #[test]
    fn correct_encode() {
        let ap_options = APOptions::new(true, true);
        let ticket = Ticket::new(
            Realm::try_from("realm".to_string()).unwrap(),
            PrincipalName::new(
                NameTypes::NtPrincipal,
                vec![KerberosString::try_from("name".to_string()).unwrap()],
            )
            .unwrap(),
            EncryptedData::new(0, 0u32, OctetString::new(&[0x0, 0x1, 0x2]).unwrap()),
        );
        let authenticator = EncryptedData::new(0, 0, OctetString::new(&[0x0, 0x1, 0x2]).unwrap());

        let msg = KrbApReq::new(ap_options, ticket, authenticator);

        let encoded_msg = msg.to_der().unwrap();

        println!("{:x?}", encoded_msg);

        #[rustfmt::skip]
        let expected_encoding = vec![
            110, 102, 48, 100, // APPLICATION 14 SEQUENCE
                160, 3, 2, 1, 5, // pvno [0] INTEGER
                161, 3, 2, 1, 14, // msg-type [1] INTEGER
                162, 7, 3, 5, 0, 96, 0, 0, 0, // ap-options [2] APOptions
                163, 58, 97, 56, 48, 54, // ticket [3] Ticket
                    160, 3, 2, 1, 5,
                    161, 7, 22, 5, 114, 101, 97, 108, 109,
                    162,17, 48, 15,
                        160, 3, 2, 1, 1,
                        161, 8, 48, 6, 22, 4, 110, 97, 109, 101,
                    163, 19, 48, 17,
                        160, 3, 2, 1, 0,
                        161, 3, 2, 1, 0,
                        162, 5, 4, 3, 0, 1, 2,
                164, 19, 48, 17, // authenticator [4] EncryptedData
                    160, 3, 2, 1, 0,
                    161, 3, 2, 1, 0,
                    162, 5, 4, 3, 0, 1, 2,
        ];

        assert_eq!(encoded_msg, expected_encoding);
    }
}
