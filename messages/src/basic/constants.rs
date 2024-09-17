use crate::back_to_enum;

back_to_enum! {
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NameTypes {
    NtUnknown = 0,
    NtPrincipal = 1,
    NtSrvInst = 2,
    NtSrcHst = 3,
    NtSrvXhst = 4,
    NtUid = 5,
    NtX500Principal = 6,
    NtSmtpName = 7,
    NtEnterprise = 10,
}
}

back_to_enum! {
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AddressTypes {
    Ipv4 = 2,
    Directional = 3,
    ChaosNet = 5,
    Xns = 6,
    Iso = 7,
    DecnetPhaseIv = 12,
    AppletalkDdp = 16,
    NetBios = 20,
    Ipv6 = 24,
}
}

back_to_enum! {
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AuthorizationDataTypes {
    IfRelevant = 1,
    KdcIssued = 4,
    AndOr = 5,
    MandatoryForKdc = 8,
}
}

back_to_enum! {
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PaDataTypes {
    PaTgsReq = 1,
    PaEncTimestamp = 2,
    PaPwSalt = 3,
    PaEtypeInfo = 11,
    PaEtypeInfo2 = 19,
}
}

pub mod flags {
    #[allow(non_camel_case_types)]
    pub enum KdcOptionsFlag {
        RESERVED = 0,                 // Bit 0
        FORWARDABLE = 1,              // Bit 1
        FORWARDED = 2,                // Bit 2
        PROXIABLE = 3,                // Bit 3
        PROXY = 4,                    // Bit 4
        ALLOW_POSTDATE = 5,             // Bit 5
        POSTDATED = 6,                // Bit 6
        INVALID = 7,                  // Bit 7
        RENEWABLE = 8,                // Bit 8
        UNUSED9 = 9,                  // Bit 9
        UNUSED10 = 10,                // Bit 10
        OPT_HARDWARE_AUTH = 11,       // Bit 11
        UNUSED12 = 12,                // Bit 12
        UNUSED13 = 13,                // Bit 13
        UNUSED15 = 15,                // Bit 15
        DISABLE_TRANSITED_CHECK = 26, // Bit 26
        RENEWABLE_OK = 27,            // Bit 27
        ENC_TKT_IN_SKEY = 28,         // Bit 28
        RENEW = 30,                   // Bit 30
        VALIDATE = 31,                // Bit 31
    }

    #[allow(non_camel_case_types)]
    pub enum TicketFlag {
        RESERVED = 0,                  // Bit 0
        FORWARDABLE = 1,               // Bit 1
        FORWARDED = 2,                 // Bit 2
        PROXIABLE = 3,                 // Bit 3
        PROXY = 4,                     // Bit 4
        MAY_POSTDATE = 5,              // Bit 5
        POSTDATED = 6,                 // Bit 6
        INVALID = 7,                   // Bit 7
        RENEWABLE = 8,                 // Bit 8
        INITIAL = 9,                   // Bit 9
        PRE_AUTHENT = 10,              // Bit 10
        HW_AUTHENT = 11,               // Bit 11
        TRANSITED_POLICY_CHECKED = 12, // Bit 12
        OK_AS_DELEGATE = 13,           // Bit 13
    }

    #[allow(non_camel_case_types)]
    pub enum APOptionsFlag {
        USE_SESSION_KEY = 1, // Bit 1
        MUTUAL_REQUIRED = 2, // Bit 2
    }
}

pub(crate) mod application_tags {
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
    #[allow(dead_code)]
    pub const RESERVED16: u8 = 16; // TGT-REQ (for user-to-user)
    #[allow(dead_code)]
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
