use der::{Decode, Encode};

use super::{atypes, ntypes, Int32};

// RFC4120 6.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameType {
    Unknown,
    Principal,
    SrvInst,
    SrcHst,
    SrvXhst,
    Uid,
    X500Principal,
    SmtpName,
    Enterprise,
}

impl Encode for NameType {
    fn encoded_len(&self) -> der::Result<der::Length> {
        Ok(self.as_der_int32().len())
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.as_der_int32().encode(encoder)
    }
}

impl<'a> Decode<'a> for NameType {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let inner = Int32::decode(decoder)?;
        NameType::try_from(inner).map_err(|_| der::Error::from(der::ErrorKind::Failed))
    }
}

impl NameType {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            NameType::Unknown => ntypes::UNKNOWN,
            NameType::Principal => ntypes::PRINCIPAL,
            NameType::SrvInst => ntypes::SRV_INST,
            NameType::SrcHst => ntypes::SRC_HST,
            NameType::SrvXhst => ntypes::SRV_XHST,
            NameType::Uid => ntypes::UID,
            NameType::X500Principal => ntypes::X500_PRINCIPAL,
            NameType::SmtpName => ntypes::SMTP_NAME,
            NameType::Enterprise => ntypes::ENTERPRISE,
        }
    }

    pub fn as_der_int32(&self) -> Int32 {
        Int32::new(self.as_bytes()).expect("This operation is always successful")
    }
}

impl TryFrom<Int32> for NameType {
    type Error = &'static str;

    fn try_from(value: Int32) -> Result<Self, Self::Error> {
        match value.as_bytes() {
            ntypes::UNKNOWN => Ok(NameType::Unknown),
            ntypes::PRINCIPAL => Ok(NameType::Principal),
            ntypes::SRV_INST => Ok(NameType::SrvInst),
            ntypes::SRC_HST => Ok(NameType::SrcHst),
            ntypes::SRV_XHST => Ok(NameType::SrvXhst),
            ntypes::UID => Ok(NameType::Uid),
            ntypes::X500_PRINCIPAL => Ok(NameType::X500Principal),
            ntypes::SMTP_NAME => Ok(NameType::SmtpName),
            ntypes::ENTERPRISE => Ok(NameType::Enterprise),
            _ => Err("Invalid NameType"),
        }
    }
}

// RFC4120 7.5.3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    IPv4,
    Directional,
    ChaosNet,
    Xns,
    Iso,
    DecnetPhaseIV,
    AppletalkDDP,
    Netbios,
    IPv6,
}

impl Encode for AddressType {
    fn encoded_len(&self) -> der::Result<der::Length> {
        Ok(self.as_der_int32().len())
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.as_der_int32().encode(encoder)
    }
}

impl<'a> Decode<'a> for AddressType {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let inner = Int32::decode(decoder)?;
        AddressType::try_from(inner).map_err(|_| der::Error::from(der::ErrorKind::Failed))
    }
}

impl AddressType {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            AddressType::IPv4 => atypes::IPV4,
            AddressType::Directional => atypes::DIRECTIONAL,
            AddressType::ChaosNet => atypes::CHAOS_NET,
            AddressType::Xns => atypes::XNS,
            AddressType::Iso => atypes::ISO,
            AddressType::DecnetPhaseIV => atypes::DECNET_PHASE_IV,
            AddressType::AppletalkDDP => atypes::APPLETALK_DDP,
            AddressType::Netbios => atypes::NETBIOS,
            AddressType::IPv6 => atypes::IPV6,
        }
    }

    pub fn as_der_int32(&self) -> Int32 {
        Int32::new(self.as_bytes()).expect("This operation is always successful")
    }
}

impl TryFrom<Int32> for AddressType {
    type Error = &'static str;

    fn try_from(value: Int32) -> Result<Self, Self::Error> {
        match value.as_bytes() {
            atypes::IPV4 => Ok(AddressType::IPv4),
            atypes::DIRECTIONAL => Ok(AddressType::Directional),
            atypes::CHAOS_NET => Ok(AddressType::ChaosNet),
            atypes::XNS => Ok(AddressType::Xns),
            atypes::ISO => Ok(AddressType::Iso),
            atypes::DECNET_PHASE_IV => Ok(AddressType::DecnetPhaseIV),
            atypes::APPLETALK_DDP => Ok(AddressType::AppletalkDDP),
            atypes::NETBIOS => Ok(AddressType::Netbios),
            atypes::IPV6 => Ok(AddressType::IPv6),
            _ => Err("Invalid AddressType"),
        }
    }
}