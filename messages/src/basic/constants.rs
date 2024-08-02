pub const DEFAULT_LEN: usize = 8;

pub const DEFAULT_PRINCIPAL_COMPONENTS_LEN: usize = 2;

pub const DEFAULT_AS_REP_ENTRIES_LEN: usize = 1;

pub mod ntypes {
    pub const UNKNOWN: &[u8] = b"\x00";
    pub const PRINCIPAL: &[u8] = b"\x01";
    pub const SRV_INST: &[u8] = b"\x02";
    pub const SRC_HST: &[u8] = b"\x03";
    pub const SRV_XHST: &[u8] = b"\x04";
    pub const UID: &[u8] = b"\x05";
    pub const X500_PRINCIPAL: &[u8] = b"\x06";
    pub const SMTP_NAME: &[u8] = b"\x07";
    pub const ENTERPRISE: &[u8] = b"\x0A";
}

pub mod atypes {
    pub const IPV4: &[u8] = b"\x02";
    pub const DIRECTIONAL: &[u8] = b"\x03";
    pub const CHAOS_NET: &[u8] = b"\x05";
    pub const XNS: &[u8] = b"\x06";
    pub const ISO: &[u8] = b"\x07";
    pub const DECNET_PHASE_IV: &[u8] = b"\x0C";
    pub const APPLETALK_DDP: &[u8] = b"\x10";
    pub const NETBIOS: &[u8] = b"\x14";
    pub const IPV6: &[u8] = b"\x18";
}

pub mod adtypes {
    pub const AD_IF_RELEVANT: &[u8] = b"\x01";
    pub const AD_KDC_ISSUED: &[u8] = b"\x04";
    pub const AD_AND_OR: &[u8] = b"\x05";
    pub const AD_MANDATORY_FOR_KDC: &[u8] = b"\x08";
}

pub mod patypes {
    pub const PA_TGS_REQ: &[u8] = b"\x01";
    pub const PA_ENC_TIMESTAMP: &[u8] = b"\x02";
    pub const PA_PW_SALT: &[u8] = b"\x03";
    pub const PA_ETYPE_INFO: &[u8] = b"\x0B";
    pub const PA_ETYPE_INFO2: &[u8] = b"\x13";
}

pub mod flags {
    pub const RESERVED: &[u8] = &[0x00, 0x00, 0x00, 0x00]; // Bit 0-7 are reserved

    pub const FORWARDABLE: &[u8] = &[0x01, 0x00, 0x00, 0x00]; // Bit 0
    pub const FORWARDED: &[u8] = &[0x02, 0x00, 0x00, 0x00]; // Bit 1
    pub const PROXIABLE: &[u8] = &[0x04, 0x00, 0x00, 0x00]; // Bit 2
    pub const PROXY: &[u8] = &[0x08, 0x00, 0x00, 0x00]; // Bit 3
    pub const MAY_POSTDATE: &[u8] = &[0x10, 0x00, 0x00, 0x00]; // Bit 4
    pub const POSTDATED: &[u8] = &[0x20, 0x00, 0x00, 0x00]; // Bit 5
    pub const INVALID: &[u8] = &[0x40, 0x00, 0x00, 0x00]; // Bit 6
    pub const RENEWABLE: &[u8] = &[0x80, 0x00, 0x00, 0x00]; // Bit 7

    pub const INITIAL: &[u8] = &[0x00, 0x01, 0x00, 0x00]; // Bit 8
    pub const PRE_AUTHENT: &[u8] = &[0x00, 0x02, 0x00, 0x00]; // Bit 9
    pub const HW_AUTHENT: &[u8] = &[0x00, 0x04, 0x00, 0x00]; // Bit 10

    pub const TRANSITED_POLICY_CHECKED: &[u8] = &[0x00, 0x08, 0x00, 0x00]; // Bit 11
    pub const OK_AS_DELEGATE: &[u8] = &[0x00, 0x10, 0x00, 0x00]; // Bit 12
}
