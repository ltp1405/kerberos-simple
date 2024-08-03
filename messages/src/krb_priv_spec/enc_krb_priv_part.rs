use der::Sequence;

use crate::basic::{HostAddress, KerberosTime, Microseconds, OctetString, UInt32};

#[derive(Sequence)]
// Missing Application tag
pub struct EncKrbPrivPart {
    #[asn1(context_specific = "0")]
    user_data: OctetString,

    #[asn1(context_specific = "1", optional = "true")]
    timestamp: Option<KerberosTime>,

    #[asn1(context_specific = "2", optional = "true")]
    usec: Option<Microseconds>,

    #[asn1(context_specific = "3", optional = "true")]
    seq_number: Option<UInt32>,

    #[asn1(context_specific = "4")]
    s_address: HostAddress,

    #[asn1(context_specific = "5", optional = "true")]
    r_address: Option<HostAddress>,
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
        Self {
            user_data,
            timestamp,
            usec,
            seq_number,
            s_address,
            r_address,
        }
    }

    pub fn user_data(&self) -> &OctetString {
        &self.user_data
    }

    pub fn timestamp(&self) -> Option<&KerberosTime> {
        self.timestamp.as_ref()
    }

    pub fn usec(&self) -> Option<&Microseconds> {
        self.usec.as_ref()
    }

    pub fn seq_number(&self) -> Option<&UInt32> {
        self.seq_number.as_ref()
    }

    pub fn s_address(&self) -> &HostAddress {
        &self.s_address
    }

    pub fn r_address(&self) -> Option<&HostAddress> {
        self.r_address.as_ref()
    }
}
