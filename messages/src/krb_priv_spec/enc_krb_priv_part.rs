use der::{FixedTag, Sequence, Tag, TagNumber};

use crate::basic::{application_tags, HostAddress, KerberosTime, Microseconds, OctetString, UInt32};

#[derive(Sequence)]
struct EncKrbPrivPartInner {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    user_data: OctetString,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    timestamp: Option<KerberosTime>,

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    usec: Option<Microseconds>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    seq_number: Option<UInt32>,

    #[asn1(context_specific = "4", tag_mode = "EXPLICIT")]
    s_address: HostAddress,

    #[asn1(context_specific = "5", tag_mode = "EXPLICIT", optional = "true")]
    r_address: Option<HostAddress>,
}

pub struct EncKrbPrivPart(EncKrbPrivPartInner);

impl EncKrbPrivPart {
    pub fn new(
        user_data: impl Into<OctetString>,
        timestamp: impl Into<Option<KerberosTime>>,
        usec: impl Into<Option<Microseconds>>,
        seq_number: impl Into<Option<UInt32>>,
        s_address: impl Into<HostAddress>,
        r_address: impl Into<Option<HostAddress>>,
    ) -> Self {
        Self(EncKrbPrivPartInner {
            user_data: user_data.into(),
            timestamp: timestamp.into(),
            usec: usec.into(),
            seq_number: seq_number.into(),
            s_address: s_address.into(),
            r_address: r_address.into(),
        })
    }

    pub fn user_data(&self) -> &OctetString {
        &self.0.user_data
    }

    pub fn timestamp(&self) -> Option<&KerberosTime> {
        self.0.timestamp.as_ref()
    }

    pub fn usec(&self) -> Option<&Microseconds> {
        self.0.usec.as_ref()
    }

    pub fn seq_number(&self) -> Option<&UInt32> {
        self.0.seq_number.as_ref()
    }

    pub fn s_address(&self) -> &HostAddress {
        &self.0.s_address
    }

    pub fn r_address(&self) -> Option<&HostAddress> {
        self.0.r_address.as_ref()
    }
}

impl FixedTag for EncKrbPrivPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_KRB_PRIV_PART),
    };
}
