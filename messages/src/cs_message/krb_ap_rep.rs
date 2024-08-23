use crate::basic::EncryptedData;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Length, Reader, Sequence, TagNumber, Writer,
};

/// KRB_AP_REP message - 5.5.1
#[derive(Debug, PartialEq, Clone)]
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

#[derive(Sequence, Debug, PartialEq, Clone)]
struct KrbApRepInner {
    #[asn1(context_specific = "0")]
    pvno: u8,

    #[asn1(context_specific = "1")]
    msg_type: u8,

    #[asn1(context_specific = "2")]
    enc_part: EncryptedData,
}

impl KrbApRep {
    pub fn new(enc_part: EncryptedData) -> Self {
        KrbApRep(KrbApRepInner {
            pvno: 5,
            msg_type: 15,
            enc_part,
        })
    }

    pub const fn pvno(&self) -> u8 {
        self.0.pvno
    }

    pub const fn msg_type(&self) -> u8 {
        self.0.msg_type
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.0.enc_part
    }
}

#[cfg(test)]
mod tests {
    use crate::basic::{EncryptedData, OctetString};
    use crate::cs_message::KrbApRep;
    use der::{Decode, Encode};

    #[test]
    fn encode_then_decode() {
        let msg = KrbApRep::new(EncryptedData::new(
            0,
            0,
            OctetString::new(b"encrypted data".to_vec()).unwrap(),
        ));
        let encoded_msg = msg.to_der().unwrap();
        println!("{:x?}", encoded_msg);

        let decoded_msg = super::KrbApRep::from_der(&encoded_msg).unwrap();

        assert_eq!(msg, decoded_msg);
    }

    #[test]
    fn correct_encode() {
        let msg = KrbApRep::new(EncryptedData::new(
            0,
            0,
            OctetString::new(b"encrypted data".to_vec()).unwrap(),
        ));

        let encoded_msg = msg.to_der().unwrap();
        #[rustfmt::skip]
        let correct_encoding = vec![
            111, 44, 48, 42, // APPLICATION 15 SEQUENCE
                160, 3, 2, 1, 5, // pvno [0] INTEGER
                161, 3, 2, 1, 15, // msg-type [1] INTEGER
                162, 30, 48, 28, // enc-part [2] EncryptedData
                    160, 3, 2, 1, 0,
                    161, 3, 2, 1, 0,
                    162, 16, 4, 14, 101, 110, 99, 114, 121, 112, 116, 101, 100, 32, 100,97, 116, 97,
        ];

        assert_eq!(encoded_msg, correct_encoding);
    }
}
