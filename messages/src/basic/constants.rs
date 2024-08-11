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

#[cfg(test)]
impl From<i32> for NameTypes {
    fn from(value: i32) -> Self {
        match value {
            0 => NameTypes::NtUnknown,
            1 => NameTypes::NtPrincipal,
            2 => NameTypes::NtSrvInst,
            3 => NameTypes::NtSrcHst,
            4 => NameTypes::NtSrvXhst,
            5 => NameTypes::NtUid,
            6 => NameTypes::NtX500Principal,
            7 => NameTypes::NtSmtpName,
            10 => NameTypes::NtEnterprise,
            _ => panic!("Invalid value for NameTypes"),
        }
    }
}

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

#[cfg(test)]
impl From<i32> for AddressTypes {
    fn from(value: i32) -> Self {
        match value {
            2 => AddressTypes::Ipv4,
            3 => AddressTypes::Directional,
            5 => AddressTypes::ChaosNet,
            6 => AddressTypes::Xns,
            7 => AddressTypes::Iso,
            12 => AddressTypes::DecnetPhaseIv,
            16 => AddressTypes::AppletalkDdp,
            20 => AddressTypes::NetBios,
            24 => AddressTypes::Ipv6,
            _ => panic!("Invalid value for AddressTypes"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AuthorizationDataTypes {
    IfRelevant = 1,
    KdcIssued = 4,
    AndOr = 5,
    MandatoryForKdc = 8,
}

impl From<i32> for AuthorizationDataTypes {
    fn from(value: i32) -> Self {
        match value {
            1 => AuthorizationDataTypes::IfRelevant,
            4 => AuthorizationDataTypes::KdcIssued,
            5 => AuthorizationDataTypes::AndOr,
            8 => AuthorizationDataTypes::MandatoryForKdc,
            _ => panic!("Invalid value for AuthorizationDataTypes"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PaDataTypes {
    PaTgsReq = 1,
    PaEncTimestamp = 2,
    PaPwSalt = 3,
    PaEtypeInfo = 11,
    PaEtypeInfo2 = 19,
}

impl From<i32> for PaDataTypes {
    fn from(value: i32) -> Self {
        match value {
            1 => PaDataTypes::PaTgsReq,
            2 => PaDataTypes::PaEncTimestamp,
            3 => PaDataTypes::PaPwSalt,
            11 => PaDataTypes::PaEtypeInfo,
            19 => PaDataTypes::PaEtypeInfo2,
            _ => panic!("Invalid value for PaDataTypes"),
        }
    }
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
