pub mod ntypes {
    pub const NT_UNKNOWN: i32 = 0;
    pub const NT_PRINCIPAL: i32 = 1;
    pub const NT_SRV_INST: i32 = 2;
    pub const NT_SRC_HST: i32 = 3;
    pub const NT_SRV_XHST: i32 = 4;
    pub const NT_UID: i32 = 5;
    pub const NT_X500_PRINCIPAL: i32 = 6;
    pub const NT_SMTP_NAME: i32 = 7;
    pub const NT_ENTERPRISE: i32 = 10;
}

pub mod atypes {
    pub const IPV4: i32 = 2;
    pub const DIRECTIONAL: i32 = 3;
    pub const CHAOS_NET: i32 = 5;
    pub const XNS: i32 = 6;
    pub const ISO: i32 = 7;
    pub const DECNET_PHASE_IV: i32 = 12;
    pub const APPLETALK_DDP: i32 = 10;
    pub const NETBIOS: i32 = 14;
    pub const IPV6: i32 = 18;
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
    pub const RESERVED: usize = 0; // Bit 0

    pub const FORWARDABLE: usize = 1; // Bit 1
    pub const FORWARDED: usize = 2; // Bit 2
    pub const PROXIABLE: usize = 3; // Bit 3
    pub const PROXY: usize = 4; // Bit 4
    pub const MAY_POSTDATE: usize = 5; // Bit 5
    pub const POSTDATED: usize = 6; // Bit 6
    pub const INVALID: usize = 7; // Bit 7
    pub const RENEWABLE: usize = 8; // Bit 8

    pub const INITIAL: usize = 9; // Bit 9
    pub const PRE_AUTHENT: usize = 10; // Bit 10
    pub const HW_AUTHENT: usize = 11; // Bit 11

    pub const TRANSITED_POLICY_CHECKED: usize = 12; // Bit 12
    pub const OK_AS_DELEGATE: usize = 13; // Bit 13

    pub const UNUSED9: usize = 9; // Bit 9
    pub const UNUSED10: usize = 10; // Bit 10
    pub const OPT_HARDWARE_AUTH: usize = 11; // Bit 11
    pub const UNUSED12: usize = 12; // Bit 12
    pub const UNUSED13: usize = 13; // Bit 13
    pub const UNUSED15: usize = 15; // Bit 15

    pub const DISABLE_TRANSITED_CHECK: usize = 26; // Bit 26
    pub const RENEWABLE_OK: usize = 27; // Bit 27
    pub const ENC_TKT_IN_SKEY: usize = 28; // Bit 28
    pub const RENEW: usize = 30; // Bit 30
    pub const VALIDATE: usize = 31; // Bit 31

    pub const USE_SESSION_KEY: usize = 1; // Bit 1
    pub const MUTUAL_REQUIRED: usize = 2; // Bit 2
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
