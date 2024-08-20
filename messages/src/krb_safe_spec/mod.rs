#[cfg(test)]
mod test;

use crate::basic::{Checksum, HostAddress, KerberosTime, Microseconds, OctetString, UInt32};
use der::asn1::ContextSpecific;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, TagMode,
    TagNumber, Writer,
};

const KRB_SAFE_PVNO: u8 = 5;
const KRB_SAFE_MSG_TYPE: u8 = 20;
const KRB_SAFE_TAG: TagNumber = TagNumber::new(20);

#[derive(Debug, PartialEq, Clone)]
pub struct KrbSafe(KrbSafeInner);

impl KrbSafe {
    pub fn builder() -> KrbSafeBuilder {
        KrbSafeBuilder::new()
    }
}

impl EncodeValue for KrbSafe {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> DecodeValue<'a> for KrbSafe {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _: Header) -> der::Result<Self> {
        let inner = KrbSafeInner::decode(reader)?;
        Ok(KrbSafe(inner))
    }
}

impl FixedTag for KrbSafe {
    const TAG: der::Tag = der::Tag::Application {
        number: KRB_SAFE_TAG,
        constructed: true,
    };
}

#[derive(Sequence, Debug, PartialEq, Clone)]
struct KrbSafeInner {
    pnvo: ContextSpecific<u8>,
    msg_type: ContextSpecific<u8>,
    safe_body: ContextSpecific<KrbSafeBody>,
    cksum: ContextSpecific<Checksum>,
}

#[derive(Sequence, Debug, PartialEq, Clone)]
pub struct KrbSafeBody {
    #[asn1(context_specific = "0")]
    user_data: OctetString,

    #[asn1(optional = "true", context_specific = "1")]
    timestamp: Option<KerberosTime>,

    #[asn1(optional = "true", context_specific = "2")]
    usec: Option<Microseconds>,

    #[asn1(optional = "true", context_specific = "3")]
    seq_number: Option<UInt32>,

    #[asn1(context_specific = "4")]
    s_address: HostAddress,

    #[asn1(optional = "true", context_specific = "5")]
    r_address: Option<HostAddress>,
}

impl KrbSafeBody {
    pub fn user_data(&self) -> &OctetString {
        &self.user_data
    }

    pub fn timestamp(&self) -> Option<&KerberosTime> {
        self.timestamp.as_ref().map(|timestamp| timestamp)
    }

    pub fn usec(&self) -> Option<&Microseconds> {
        self.usec.as_ref().map(|usec| usec)
    }

    pub fn seq_number(&self) -> Option<&UInt32> {
        self.seq_number.as_ref().map(|seq_number| seq_number)
    }

    pub fn s_address(&self) -> &HostAddress {
        &self.s_address
    }

    pub fn r_address(&self) -> Option<&HostAddress> {
        self.r_address.as_ref().map(|r_address| r_address)
    }
}

pub struct KrbSafeBuilder {
    user_data: Option<OctetString>,
    timestamp: Option<KerberosTime>,
    usec: Option<Microseconds>,
    seq_number: Option<UInt32>,
    s_address: Option<HostAddress>,
    r_address: Option<HostAddress>,
    cksum: Option<Checksum>,
}

impl KrbSafeBuilder {
    pub fn new() -> Self {
        KrbSafeBuilder {
            user_data: None,
            timestamp: None,
            usec: None,
            seq_number: None,
            s_address: None,
            r_address: None,
            cksum: None,
        }
    }

    pub fn set_user_data(mut self, user_data: OctetString) -> Self {
        self.user_data = Some(user_data);
        self
    }

    pub fn set_timestamp(mut self, timestamp: KerberosTime) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn set_usec(mut self, usec: Microseconds) -> Self {
        self.usec = Some(usec);
        self
    }

    pub fn set_seq_number(mut self, seq_number: UInt32) -> Self {
        self.seq_number = Some(seq_number);
        self
    }

    pub fn set_s_address(mut self, s_address: HostAddress) -> Self {
        self.s_address = Some(s_address);
        self
    }

    pub fn set_r_address(mut self, r_address: HostAddress) -> Self {
        self.r_address = Some(r_address);
        self
    }

    pub fn set_cksum(mut self, cksum: Checksum) -> Self {
        self.cksum = Some(cksum);
        self
    }

    pub fn build(self) -> Result<KrbSafe, &'static str> {
        fn make_err(field: &'static str) -> Result<KrbSafe, &'static str> {
            Err(&format!("{} is required", field))
        }
        if self.user_data.is_none() {
            return make_err("user_data");
        }
        if self.s_address.is_none() {
            return make_err("s_address");
        }
        if self.cksum.is_none() {
            return make_err("cksum");
        }
        Ok(self.build_unsafe())
    }

    pub fn build_unsafe(self) -> KrbSafe {
        fn make_tag<T>(value: T, number: u8) -> ContextSpecific<T> {
            ContextSpecific {
                value,
                tag_number: TagNumber::new(number),
                tag_mode: TagMode::Explicit,
            }
        }
        KrbSafe(KrbSafeInner {
            pnvo: make_tag(KRB_SAFE_PVNO, 0),
            msg_type: make_tag(KRB_SAFE_MSG_TYPE, 1),
            safe_body: make_tag(
                KrbSafeBody {
                    user_data: self.user_data.expect("user_data is required"),
                    timestamp: self.timestamp.map(|timestamp| timestamp),
                    usec: self.usec.map(|usec| usec),
                    seq_number: self.seq_number.map(|seq_number| seq_number),
                    s_address: self.s_address.expect("s_address is required"),
                    r_address: self.r_address.map(|r_address| r_address),
                },
                2,
            ),
            cksum: make_tag(self.cksum.expect("cksum is required"), 3),
        })
    }
}
