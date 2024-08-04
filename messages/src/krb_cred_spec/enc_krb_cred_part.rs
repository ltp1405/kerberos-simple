use der::{FixedTag, Sequence, Tag, TagNumber};

use crate::basic::{application_tags, HostAddress, KerberosTime, Microseconds, SequenceOf, UInt32};
use crate::krb_cred_spec::krb_cred_info::KrbCredInfo;

#[derive(Sequence)]
pub struct EncKrbCredPartInner {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    ticket_info: SequenceOf<KrbCredInfo>,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    nonce: Option<UInt32>,

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    timestamp: Option<KerberosTime>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    usec: Option<Microseconds>,

    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", optional = "true")]
    s_address: Option<HostAddress>,

    #[asn1(context_specific = "5", tag_mode = "EXPLICIT", optional = "true")]
    r_address: Option<HostAddress>,
}

pub struct EncKrbCredPart {
    inner: EncKrbCredPartInner,
}

impl EncKrbCredPart {
    pub fn new(
        ticket_info: SequenceOf<KrbCredInfo>,
        nonce: Option<UInt32>,
        timestamp: Option<KerberosTime>,
        usec: Option<Microseconds>,
        s_address: Option<HostAddress>,
        r_address: Option<HostAddress>,
    ) -> Self {
        let inner = EncKrbCredPartInner {
            ticket_info,
            nonce,
            timestamp,
            usec,
            s_address,
            r_address,
        };
        Self { inner }
    }

    pub fn ticket_info(&self) -> &SequenceOf<KrbCredInfo> {
        &self.inner.ticket_info
    }

    pub fn nonce(&self) -> Option<&UInt32> {
        self.inner.nonce.as_ref()
    }

    pub fn timestamp(&self) -> Option<&KerberosTime> {
        self.inner.timestamp.as_ref()
    }

    pub fn usec(&self) -> Option<&Microseconds> {
        self.inner.usec.as_ref()
    }

    pub fn s_address(&self) -> Option<&HostAddress> {
        self.inner.s_address.as_ref()
    }

    pub fn r_address(&self) -> Option<&HostAddress> {
        self.inner.r_address.as_ref()
    }
}

impl FixedTag for EncKrbCredPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_KRB_CRED_PART),
    };
}