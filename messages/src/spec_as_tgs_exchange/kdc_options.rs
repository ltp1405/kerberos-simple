use crate::basic::{flags, KerberosFlags};

pub type KdcOptions = KerberosFlags;

impl KdcOptions {
    pub fn disable_transited_check(&self) -> Self {
        Self::builder()
            .set(flags::KdcOptionsFlag::DISABLE_TRANSITED_CHECK as usize)
            .build()
            .expect("Cannot fail")
    }

    pub fn enc_tkt_in_skey(&self) -> Self {
        Self::builder()
            .set(flags::KdcOptionsFlag::ENC_TKT_IN_SKEY as usize)
            .build()
            .expect("Cannot fail")
    }

    pub fn renewable_ok(&self) -> Self {
        Self::builder()
            .set(flags::KdcOptionsFlag::RENEWABLE_OK as usize)
            .build()
            .expect("Cannot fail")
    }

    pub fn renew(&self) -> Self {
        Self::builder()
            .set(flags::KdcOptionsFlag::RENEW as usize)
            .build()
            .expect("Cannot fail")
    }

    pub fn validate(&self) -> Self {
        Self::builder()
            .set(flags::KdcOptionsFlag::VALIDATE as usize)
            .build()
            .expect("Cannot fail")
    }
}
