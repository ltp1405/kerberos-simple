use crate::basic::{flags, KerberosFlags};

pub type KdcOptions = KerberosFlags;

impl KdcOptions {
    pub fn disable_transited_check(&self) -> Self {
        Self::try_from(flags::DISABLE_TRANSITED_CHECK).expect("Cannot fail")
    }

    pub fn enc_tkt_in_skey(&self) -> Self {
        Self::try_from(flags::ENC_TKT_IN_SKEY).expect("Cannot fail")
    }

    pub fn renewable_ok(&self) -> Self {
        Self::try_from(flags::RENEWABLE_OK).expect("Cannot fail")
    }

    pub fn renew(&self) -> Self {
        Self::try_from(flags::RENEW).expect("Cannot fail")
    }

    pub fn validate(&self) -> Self {
        Self::try_from(flags::VALIDATE).expect("Cannot fail")
    }
}