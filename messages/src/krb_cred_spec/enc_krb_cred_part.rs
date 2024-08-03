use der::Sequence;

use crate::basic::{HostAddress, KerberosTime, Microseconds, SequenceOf, UInt32};
use crate::krb_cred_spec::krb_cred_info::KrbCredInfo;

#[derive(Sequence)]
pub struct EncKrbCredPart {
    #[asn1(context_specific = "0")]
    ticket_info: SequenceOf<KrbCredInfo>,

    #[asn1(context_specific = "1", optional = "true")]
    nonce: Option<UInt32>,

    #[asn1(context_specific = "2", optional = "true")]
    timestamp: Option<KerberosTime>,

    #[asn1(context_specific = "3", optional = "true")]
    usec: Option<Microseconds>,

    #[asn1(context_specific = "4", optional = "true")]
    s_address: Option<HostAddress>,

    #[asn1(context_specific = "5", optional = "true")]
    r_address: Option<HostAddress>,
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
        Self {
            ticket_info,
            nonce,
            timestamp,
            usec,
            s_address,
            r_address,
        }
    }

    pub fn ticket_info(&self) -> &SequenceOf<KrbCredInfo> {
        &self.ticket_info
    }

    pub fn nonce(&self) -> Option<&UInt32> {
        self.nonce.as_ref()
    }

    pub fn timestamp(&self) -> Option<&KerberosTime> {
        self.timestamp.as_ref()
    }

    pub fn usec(&self) -> Option<&Microseconds> {
        self.usec.as_ref()
    }

    pub fn s_address(&self) -> Option<&HostAddress> {
        self.s_address.as_ref()
    }

    pub fn r_address(&self) -> Option<&HostAddress> {
        self.r_address.as_ref()
    }
}