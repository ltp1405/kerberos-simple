use crate::basic::{flags, KerberosFlags};

pub type KdcOptions = KerberosFlags;

impl KdcOptions {
    pub fn disable_transited_check(&self) -> Self {
        Self::builder()
            .set(flags::DISABLE_TRANSITED_CHECK)
            .build()
            .expect("Cannot fail")
    }

    pub fn enc_tkt_in_skey(&self) -> Self {
        Self::builder()
            .set(flags::ENC_TKT_IN_SKEY)
            .build()
            .expect("Cannot fail")
    }

    pub fn renewable_ok(&self) -> Self {
        Self::builder()
            .set(flags::RENEWABLE_OK)
            .build()
            .expect("Cannot fail")
    }

    pub fn renew(&self) -> Self {
        Self::builder()
            .set(flags::RENEW)
            .build()
            .expect("Cannot fail")
    }

    pub fn validate(&self) -> Self {
        Self::builder()
            .set(flags::VALIDATE)
            .build()
            .expect("Cannot fail")
    }
}
