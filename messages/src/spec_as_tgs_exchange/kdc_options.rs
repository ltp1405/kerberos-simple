use crate::basic::KerberosFlags;

pub type KdcOptions = KerberosFlags;

impl KdcOptions {
    pub fn disable_transited_check(&self) -> Self {
        Self::builder()
            .set_disable_transited_check()
            .build()
            .expect("Cannot fail")
    }

    pub fn enc_tkt_in_skey(&self) -> Self {
        Self::builder()
            .set_enc_tkt_in_skey()
            .build()
            .expect("Cannot fail")
    }

    pub fn renewable_ok(&self) -> Self {
        Self::builder()
            .set_renewable_ok()
            .build()
            .expect("Cannot fail")
    }

    pub fn renew(&self) -> Self {
        Self::builder().set_renew().build().expect("Cannot fail")
    }

    pub fn validate(&self) -> Self {
        Self::builder().set_validate().build().expect("Cannot fail")
    }
}
