use chrono::{DateTime, Local, RoundingError, TimeZone};
use der::asn1::GeneralizedTime;
use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};
use std::ops::Deref;
use std::time::{Duration, SystemTime};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct KerberosTime(GeneralizedTime);

impl FixedTag for KerberosTime {
    const TAG: Tag = Tag::GeneralizedTime;
}

impl<'a> DecodeValue<'a> for KerberosTime {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        Ok(KerberosTime(GeneralizedTime::decode_value(reader, header)?))
    }
}

impl EncodeValue for KerberosTime {
    fn value_len(&self) -> der::Result<Length> {
        self.0.value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        Ok(self.0.encode_value(encoder)?)
    }
}

impl KerberosTime {
    pub fn from_system_time(time: SystemTime) -> Result<KerberosTime, der::Error> {
        Ok(KerberosTime(GeneralizedTime::from_system_time(time)?))
    }

    pub fn from_unix_duration(duration: Duration) -> der::Result<KerberosTime> {
        Ok(KerberosTime(GeneralizedTime::from_unix_duration(duration)?))
    }

    pub fn from_chrono_datetime<Tz: TimeZone>(
        time: DateTime<Tz>,
    ) -> Result<KerberosTime, der::Error> {
        Ok(KerberosTime::from_unix_duration(Duration::from_secs(
            time.timestamp() as u64,
        ))?)
    }

    pub fn from_date_time(date_time: der::DateTime) -> Self {
        KerberosTime(GeneralizedTime::from_date_time(date_time))
    }

    pub fn to_unix_duration(&self) -> Duration {
        self.0.to_unix_duration()
    }
}
