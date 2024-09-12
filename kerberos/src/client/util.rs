use messages::basic_types::KerberosTime;
use rand::Rng;
use std::time::Duration;

pub(crate) fn generate_nonce() -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen()
}

pub(crate) fn is_within_clock_skew(
    time: Duration,
    reference_time: Duration,
    clock_skew: Duration,
) -> bool {
    reference_time <= time + clock_skew && time <= reference_time + clock_skew
}

pub(crate) fn is_zero_time(time: impl Into<KerberosTime>) -> bool {
    let time: KerberosTime = time.into();
    time.to_unix_duration() == Duration::from_secs(0)
}
