use der::Sequence;

use crate::basic::{Int32, KerberosTime, SequenceOf};

#[derive(Sequence, Eq, PartialEq, Debug)]
pub struct LastReqEntry {
    #[asn1(context_specific = "0")]
    pub lr_type: Int32,

    #[asn1(context_specific = "1")]
    pub lr_value: KerberosTime,
}

impl LastReqEntry {
    pub fn new(lr_type: impl Into<Int32>, lr_value: impl Into<KerberosTime>) -> Self {
        Self {
            lr_type: lr_type.into(),
            lr_value: lr_value.into(),
        }
    }

    pub fn lr_type(&self) -> &Int32 {
        &self.lr_type
    }

    pub fn lr_value(&self) -> &KerberosTime {
        &self.lr_value
    }
}

pub type LastReq = SequenceOf<LastReqEntry>;

#[cfg(test)]
mod tests {
    use crate::basic::{Int32, KerberosTime};
    use crate::spec_as_tgs_exchange::last_req::{LastReq, LastReqEntry};
    use der::{Decode, Encode, SliceReader};
    use std::time::Duration;

    fn sample_data() -> LastReq {
        vec![
            LastReqEntry::new(
                Int32::new(b"1").unwrap(),
                KerberosTime::from_unix_duration(Duration::from_secs(2)).unwrap(),
            ),
            LastReqEntry::new(
                Int32::new(b"3").unwrap(),
                KerberosTime::from_unix_duration(Duration::from_secs(4)).unwrap(),
            ),
        ]
    }

    #[test]
    fn test_primitives() {
        let data = sample_data();
        assert_eq!(data.len(), 2);
        assert_eq!(*data[0].lr_type(), Int32::new(b"1").unwrap());
        assert_eq!(
            *data[0].lr_value(),
            KerberosTime::from_unix_duration(Duration::from_secs(2)).unwrap()
        );
        assert_eq!(*data[1].lr_type(), Int32::new(b"3").unwrap());
        assert_eq!(
            *data[1].lr_value(),
            KerberosTime::from_unix_duration(Duration::from_secs(4)).unwrap()
        );
    }

    #[test]
    fn verify_encode_decode() {
        let data = sample_data();
        let mut buf = Vec::new();
        data.encode_to_vec(&mut buf).unwrap();
        let decoded = LastReq::decode(&mut SliceReader::new(buf.as_mut_slice()).unwrap()).unwrap();
        assert_eq!(data, decoded);
    }
}
