use crate::basic::{Checksum, HostAddress, KerberosTime, Microseconds, OctetString, UInt32};
use der::asn1::ContextSpecific;
use der::{Decode, Encode, FixedTag, Reader, Sequence, TagMode, TagNumber, Writer};

const KRB_SAFE_PVNO: u8 = 5;
const KRB_SAFE_MSG_TYPE: u8 = 20;
const KRB_SAFE_TAG: TagNumber = TagNumber::new(20);

#[derive(Debug, PartialEq, Clone)]
pub struct KrbSafe(KrbSafeInner);

impl KrbSafe {
    fn builder() -> KrbSafeBuilder {
        KrbSafeBuilder::new()
    }
}

impl Encode for KrbSafe {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.0.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> Decode<'a> for KrbSafe {
    fn decode<R: Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let inner = KrbSafeInner::decode(decoder)?;
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
    user_data: ContextSpecific<OctetString>,
    timestamp: Option<ContextSpecific<KerberosTime>>,
    usec: Option<ContextSpecific<Microseconds>>,
    seq_number: Option<ContextSpecific<UInt32>>,
    s_address: ContextSpecific<HostAddress>,
    r_address: Option<ContextSpecific<HostAddress>>,
}

impl KrbSafeBody {
    fn user_data(&self) -> &OctetString {
        &self.user_data.value
    }

    fn timestamp(&self) -> Option<&KerberosTime> {
        self.timestamp.as_ref().map(|timestamp| &timestamp.value)
    }

    fn usec(&self) -> Option<&Microseconds> {
        self.usec.as_ref().map(|usec| &usec.value)
    }

    fn seq_number(&self) -> Option<&UInt32> {
        self.seq_number.as_ref().map(|seq_number| &seq_number.value)
    }

    fn s_address(&self) -> &HostAddress {
        &self.s_address.value
    }

    fn r_address(&self) -> Option<&HostAddress> {
        self.r_address.as_ref().map(|r_address| &r_address.value)
    }
}

#[derive(Debug)]
pub struct KrbSafeBuildError {
    missing_field: &'static str,
}

impl std::fmt::Display for KrbSafeBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "field is required: {}", self.missing_field)
    }
}

impl std::error::Error for KrbSafeBuildError {}

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

    pub fn build(self) -> Result<KrbSafe, KrbSafeBuildError> {
        if self.user_data.is_none() {
            return Err(KrbSafeBuildError {
                missing_field: "user_data",
            });
        }
        if self.s_address.is_none() {
            return Err(KrbSafeBuildError {
                missing_field: "s_address",
            });
        }
        if self.cksum.is_none() {
            return Err(KrbSafeBuildError {
                missing_field: "cksum",
            });
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
                    user_data: make_tag(self.user_data.expect("user_data is required"), 0),
                    timestamp: self.timestamp.map(|timestamp| make_tag(timestamp, 1)),
                    usec: self.usec.map(|usec| make_tag(usec, 2)),
                    seq_number: self.seq_number.map(|seq_number| make_tag(seq_number, 3)),
                    s_address: make_tag(self.s_address.expect("s_address is required"), 4),
                    r_address: self.r_address.map(|r_address| make_tag(r_address, 5)),
                },
                2,
            ),
            cksum: make_tag(self.cksum.expect("cksum is required"), 3),
        })
    }
}
