use crate::basic::Microseconds;
use chrono::{DateTime, Local, TimeZone};
use der::asn1::GeneralizedTime;
use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};
use std::ops::{Add, AddAssign, Sub, SubAssign};
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
    ) -> Option<(KerberosTime, Microseconds)> {
        KerberosTime::from_unix_duration(Duration::from_secs(time.timestamp() as u64))
            .ok()
            .map(|t| (t, time.timestamp_subsec_micros() as Microseconds))
    }

    pub fn from_date_time(date_time: der::DateTime) -> Self {
        KerberosTime(GeneralizedTime::from_date_time(date_time))
    }

    pub fn from_timestamp(seconds: u64) -> Option<Self> {
        KerberosTime::from_unix_duration(Duration::from_secs(seconds)).ok()
    }

    pub fn now() -> Self {
        KerberosTime::from_unix_duration(Duration::from_secs(Local::now().timestamp() as u64))
            .expect("Should not failed")
    }

    pub fn to_unix_duration(&self) -> Duration {
        self.0.to_unix_duration()
    }

    pub fn checked_add_duration(self, rhs: Duration) -> Option<KerberosTime> {
        let new_dur = self.0.to_unix_duration() + rhs;
        GeneralizedTime::from_unix_duration(new_dur)
            .ok()
            .map(KerberosTime)
    }

    pub fn timestamp(&self) -> i64 {
        self.0.to_unix_duration().as_secs() as i64
    }
}

impl Add<Duration> for KerberosTime {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        let new_dur = self.0.to_unix_duration() + rhs;
        KerberosTime(GeneralizedTime::from_unix_duration(new_dur).expect("Overflow"))
    }
}

impl Sub<KerberosTime> for KerberosTime {
    type Output = Duration;

    fn sub(self, rhs: KerberosTime) -> Self::Output {
        self.0.to_unix_duration() - rhs.0.to_unix_duration()
    }
}

impl Sub<Duration> for KerberosTime {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        let new_dur = self.0.to_unix_duration() - rhs;
        KerberosTime(GeneralizedTime::from_unix_duration(new_dur).expect("Overflow"))
    }
}

impl AddAssign<Duration> for KerberosTime {
    fn add_assign(&mut self, rhs: Duration) {
        let new_dur = self.0.to_unix_duration() + rhs;
        self.0 = GeneralizedTime::from_unix_duration(new_dur).expect("Overflow")
    }
}

impl SubAssign<Duration> for KerberosTime {
    fn sub_assign(&mut self, rhs: Duration) {
        let new_dur = self.0.to_unix_duration() - rhs;
        self.0 = GeneralizedTime::from_unix_duration(new_dur).expect("Overflow")
    }
}

#[cfg(test)]
mod tests {
    use crate::basic::KerberosTime;
    use std::time::Duration;

    #[test]
    #[should_panic]
    fn add_overflow_unchecked() {
        let t = KerberosTime::from_unix_duration(Duration::from_secs(10000)).unwrap();
        let t = t + Duration::from_secs(10e15 as u64);
    }

    #[test]
    fn add_overflow_check() {
        let t = KerberosTime::from_unix_duration(Duration::from_secs(10000)).unwrap();
        assert!(t
            .checked_add_duration(Duration::from_secs(10e15 as u64))
            .is_none());
    }

    #[test]
    fn correct_add() {
        let mut t = KerberosTime::from_unix_duration(Duration::from_secs(10000)).unwrap();
        t += Duration::from_secs(1000);
        assert_eq!(
            t,
            KerberosTime::from_unix_duration(Duration::from_secs(11000)).unwrap()
        );
    }
}
