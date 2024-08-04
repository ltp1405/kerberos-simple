use der::{FixedTag, Sequence, Tag, TagNumber};

use crate::basic::{application_tags, HostAddress, KerberosTime, Microseconds, OctetString, UInt32};

#[derive(Sequence)]
pub struct EncKrbPrivPartInner {
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

pub struct EncKrbPrivPart {
    inner: EncKrbPrivPartInner,
}

impl EncKrbPrivPart {
    pub fn new(
        user_data: OctetString,
        timestamp: Option<KerberosTime>,
        usec: Option<Microseconds>,
        seq_number: Option<UInt32>,
        s_address: HostAddress,
        r_address: Option<HostAddress>,
    ) -> Self {
        let inner = EncKrbPrivPartInner {
            user_data,
            timestamp,
            usec,
            seq_number,
            s_address,
            r_address,
        };
        Self { inner }
    }

    pub fn user_data(&self) -> &OctetString {
        &self.inner.user_data
    }

    pub fn timestamp(&self) -> Option<&KerberosTime> {
        self.inner.timestamp.as_ref()
    }

    pub fn usec(&self) -> Option<&Microseconds> {
        self.inner.usec.as_ref()
    }

    pub fn seq_number(&self) -> Option<&UInt32> {
        self.inner.seq_number.as_ref()
    }

    pub fn s_address(&self) -> &HostAddress {
        &self.inner.s_address
    }

    pub fn r_address(&self) -> Option<&HostAddress> {
        self.inner.r_address.as_ref()
    }
}

impl FixedTag for EncKrbPrivPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_KRB_PRIV_PART),
    };
}
