pub mod ntypes {
    pub const UNKNOWN: i32 = 0x00;
    pub const PRINCIPAL: i32 = 0x01;
    pub const SRV_INST: i32 = 0x02;
    pub const SRC_HST: i32 = 0x03;
    pub const SRV_XHST: i32 = 0x04;
    pub const UID: i32 = 0x05;
    pub const X500_PRINCIPAL: i32 = 0x06;
    pub const SMTP_NAME: i32 = 0x07;
    pub const ENTERPRISE: i32 = 0x0A;
}

pub mod atypes {
    pub const IPV4: i32 = 0x02;
    pub const DIRECTIONAL: i32 = 0x03;
    pub const CHAOS_NET: i32 = 0x05;
    pub const XNS: i32 = 0x06;
    pub const ISO: i32 = 0x07;
    pub const DECNET_PHASE_IV: i32 = 0x0C;
    pub const APPLETALK_DDP: i32 = 0x10;
    pub const NETBIOS: i32 = 0x14;
    pub const IPV6: i32 = 0x18;
}

pub mod adtypes {
    pub const AD_IF_RELEVANT: i32 = 0x01;
    pub const AD_KDC_ISSUED: i32 = 0x04;
    pub const AD_AND_OR: i32 = 0x05;
    pub const AD_MANDATORY_FOR_KDC: i32 = 0x08;
}

pub mod patypes {
    pub const PA_TGS_REQ: i32 = 0x01;
    pub const PA_ENC_TIMESTAMP: i32 = 0x02;
    pub const PA_PW_SALT: i32 = 0x03;
    pub const PA_ETYPE_INFO: i32 = 0x0B;
    pub const PA_ETYPE_INFO2: i32 = 0x13;
}

pub mod flags {
    pub const RESERVED: u8 = 0b0000_0001; // Bit 0

    pub const FORWARDABLE: u8 = 0b0000_0010; // Bit 1
    pub const FORWARDED: u8 = 0b0000_0100; // Bit 2
    pub const PROXIABLE: u8 = 0b0000_1000; // Bit 3
    pub const PROXY: u8 = 0b0001_0000; // Bit 4
    pub const MAY_POSTDATE: u8 = 0b0010_0000; // Bit 5
    pub const POSTDATED: u8 = 0b0100_0000; // Bit 6
    pub const INVALID: u8 = 0b1000_0000; // Bit 7
    pub const RENEWABLE: u8 = 0b0000_0001; // Bit 8

    pub const INITIAL: u8 = 0b0000_0010; // Bit 9
    pub const PRE_AUTHENT: u8 = 0b0000_0100; // Bit 10
    pub const HW_AUTHENT: u8 = 0b0000_1000; // Bit 11

    pub const TRANSITED_POLICY_CHECKED: u8 = 0b0001_0000; // Bit 12
    pub const OK_AS_DELEGATE: u8 = 0b0010_0000; // Bit 13

    pub const DISABLE_TRANSITED_CHECK: u8 = 0b0000_0100; // Bit 26
    pub const RENEWABLE_OK: u8 = 0b0000_1000; // Bit 27
    pub const ENC_TKT_IN_SKEY: u8 = 0b0001_0000; // Bit 28
    pub const RENEW: u8 = 0b0100_0000; // Bit 30
    pub const VALIDATE: u8 = 0b1000_0000; // Bit 31
}

pub mod application_tags {
    // 0 unused
    pub const TICKET: u8 = 1;
    pub const AUTHENTICATOR: u8 = 2;
    pub const ENC_TICKET_PART: u8 = 3;

    // 4-9 unused
    pub const AS_REQ: u8 = 10;
    pub const AS_REP: u8 = 11;
    pub const TGS_REQ: u8 = 12;
    pub const TGS_REP: u8 = 13;
    pub const AP_REQ: u8 = 14;
    pub const AP_REP: u8 = 15;
    pub const RESERVED16: u8 = 16; // TGT-REQ (for user-to-user)
    pub const RESERVED17: u8 = 17; // TGT-REP (for user-to-user)

    // 18-19 unused
    pub const KRB_SAFE: u8 = 20;
    pub const KRB_PRIV: u8 = 21;
    pub const KRB_CRED: u8 = 22;

    // 23-24 unused
    pub const ENC_AS_REP_PART: u8 = 25;
    pub const ENC_TGS_REP_PART: u8 = 26;
    pub const ENC_AP_REP_PART: u8 = 27;
    pub const ENC_KRB_PRIV_PART: u8 = 28;
    pub const ENC_KRB_CRED_PART: u8 = 29;
    pub const KRB_ERROR: u8 = 30;
}
