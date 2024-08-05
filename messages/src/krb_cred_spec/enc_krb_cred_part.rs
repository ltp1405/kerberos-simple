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

pub struct EncKrbCredPart(EncKrbCredPartInner);

impl EncKrbCredPart {
    pub fn new(
        ticket_info: impl Into<SequenceOf<KrbCredInfo>>,
        nonce: impl Into<Option<UInt32>>,
        timestamp: impl Into<Option<KerberosTime>>,
        usec: impl Into<Option<Microseconds>>,
        s_address: impl Into<Option<HostAddress>>,
        r_address: impl Into<Option<HostAddress>>,
    ) -> Self {
        let inner = EncKrbCredPartInner {
            ticket_info: ticket_info.into(),
            nonce: nonce.into(),
            timestamp: timestamp.into(),
            usec: usec.into(),
            s_address: s_address.into(),
            r_address: r_address.into(),
        };

        Self(inner)
    }

    pub fn ticket_info(&self) -> &SequenceOf<KrbCredInfo> {
        &self.0.ticket_info
    }

    pub fn nonce(&self) -> Option<&UInt32> {
        self.0.nonce.as_ref()
    }

    pub fn timestamp(&self) -> Option<&KerberosTime> {
        self.0.timestamp.as_ref()
    }

    pub fn usec(&self) -> Option<&Microseconds> {
        self.0.usec.as_ref()
    }

    pub fn s_address(&self) -> Option<&HostAddress> {
        self.0.s_address.as_ref()
    }

    pub fn r_address(&self) -> Option<&HostAddress> {
        self.0.r_address.as_ref()
    }
}

impl FixedTag for EncKrbCredPart {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_KRB_CRED_PART),
    };
}