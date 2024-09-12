use der::Sequence;

use crate::basic::{Int32, OctetString};

#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct TransitedEncoding {
    #[asn1(context_specific = "0")]
    tr_type: Int32, // must be registered
    #[asn1(context_specific = "1")]
    contents: OctetString,
}

impl TransitedEncoding {
    pub fn empty(tr_type: Int32) -> Self {
        Self {
            tr_type,
            contents: OctetString::new(Vec::new()).unwrap(),
        }
    }
    pub fn new(tr_type: Int32, contents: OctetString) -> Self {
        Self { tr_type, contents }
    }

    pub fn tr_type(&self) -> &Int32 {
        &self.tr_type
    }

    pub fn contents(&self) -> &OctetString {
        &self.contents
    }
}
