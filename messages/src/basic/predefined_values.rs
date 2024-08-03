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
        self.as_der_int32().encoded_len()
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.as_der_int32().encode(encoder)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for NameType {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let inner = Int32::decode(decoder)?;
        NameType::try_from(inner).map_err(|_| der::Error::from(der::ErrorKind::Failed))
    }
}

impl NameType {
    pub fn as_bytes(&self) -> Vec<u8> {
        let value = match self {
            NameType::Unknown => ntypes::UNKNOWN.to_der(),
            NameType::Principal => ntypes::PRINCIPAL.to_der(),
            NameType::SrvInst => ntypes::SRV_INST.to_der(),
            NameType::SrcHst => ntypes::SRC_HST.to_der(),
            NameType::SrvXhst => ntypes::SRV_XHST.to_der(),
            NameType::Uid => ntypes::UID.to_der(),
            NameType::X500Principal => ntypes::X500_PRINCIPAL.to_der(),
            NameType::SmtpName => ntypes::SMTP_NAME.to_der(),
            NameType::Enterprise => ntypes::ENTERPRISE.to_der(),
        };
        value.expect("This operation is always successful")
    }

    pub fn as_der_int32(&self) -> Int32 {
        Int32::from_der(&self.as_bytes()).expect("This operation is always successful")
    }
}

impl TryFrom<Int32> for NameType {
    type Error = &'static str;

    fn try_from(value: Int32) -> Result<Self, Self::Error> {
        let bytes = value.to_der().map_err(|e| {
            eprintln!("Error: {:?}", e);
            "Failed to apply to_der on Int32"
        })?;
        let decoded = i32::from_der(&bytes).map_err(|e| {
            eprintln!("Error: {:?}", e);
            "Failed to calling from_der on i32"
        })?;
        match decoded {
            ntypes::UNKNOWN => Ok(NameType::Unknown),
            ntypes::PRINCIPAL => Ok(NameType::Principal),
            ntypes::SRV_INST => Ok(NameType::SrvInst),
            ntypes::SRC_HST => Ok(NameType::SrcHst),
            ntypes::SRV_XHST => Ok(NameType::SrvXhst),
            ntypes::UID => Ok(NameType::Uid),
            ntypes::X500_PRINCIPAL => Ok(NameType::X500Principal),
            ntypes::SMTP_NAME => Ok(NameType::SmtpName),
            ntypes::ENTERPRISE => Ok(NameType::Enterprise),
            _ => Err("Unsupported Int32 value"),
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
        self.as_der_int32().encoded_len()
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
    pub fn as_bytes(&self) -> Vec<u8> {
        let value = match self {
            AddressType::IPv4 => atypes::IPV4.to_der(),
            AddressType::Directional => atypes::DIRECTIONAL.to_der(),
            AddressType::ChaosNet => atypes::CHAOS_NET.to_der(),
            AddressType::Xns => atypes::XNS.to_der(),
            AddressType::Iso => atypes::ISO.to_der(),
            AddressType::DecnetPhaseIV => atypes::DECNET_PHASE_IV.to_der(),
            AddressType::AppletalkDDP => atypes::APPLETALK_DDP.to_der(),
            AddressType::Netbios => atypes::NETBIOS.to_der(),
            AddressType::IPv6 => atypes::IPV6.to_der(),
        };
        value.expect("This operation is always successful")
    }

    pub fn as_der_int32(&self) -> Int32 {
        Int32::from_der(&self.as_bytes()).expect("This operation is always successful")
    }
}

impl TryFrom<Int32> for AddressType {
    type Error = &'static str;

    fn try_from(value: Int32) -> Result<Self, Self::Error> {
        let bytes = value.to_der().map_err(|e| {
            eprintln!("Error: {:?}", e);
            "Failed to apply to_der on Int32"
        })?;
        let decoded = i32::from_der(&bytes).map_err(|e| {
            eprintln!("Error: {:?}", e);
            "Failed to calling from_der on i32"
        })?;
        match decoded {
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

#[cfg(test)]
mod test {
    use crate::basic::atypes;
    use crate::basic::predefined_values::AddressType;
    use der::{Decode, Encode};

    use crate::basic::{ntypes, predefined_values::NameType, Int32};

    #[test]
    fn name_typed_should_provide_as_bytes_correctly() {
        let testcases = vec![
            (NameType::Principal, ntypes::PRINCIPAL),
            (NameType::SrvInst, ntypes::SRV_INST),
            (NameType::SrcHst, ntypes::SRC_HST),
            (NameType::SrvXhst, ntypes::SRV_XHST),
            (NameType::Uid, ntypes::UID),
            (NameType::X500Principal, ntypes::X500_PRINCIPAL),
            (NameType::SmtpName, ntypes::SMTP_NAME),
            (NameType::Enterprise, ntypes::ENTERPRISE),
        ];

        for (ntype, expected) in testcases {
            let bytes = ntype.as_bytes();
            assert_eq!(bytes, expected.to_der().unwrap());
        }
    }

    #[test]
    fn name_typed_should_panic_when_given_non_mapped_value() {
        let testcases = vec![-1, -9, i32::MIN];
        for test in testcases {
            let der_i32 = Int32::from_der(&test.to_der().unwrap()).unwrap();
            assert!(std::panic::catch_unwind(|| NameType::try_from(der_i32).unwrap()).is_err());
        }
    }

    #[test]
    fn name_typed_should_map_to_corres_enum_variants_when_given_correct_value() {
        let testcases = vec![
            (NameType::Principal, ntypes::PRINCIPAL),
            (NameType::SrvInst, ntypes::SRV_INST),
            (NameType::SrcHst, ntypes::SRC_HST),
            (NameType::SrvXhst, ntypes::SRV_XHST),
            (NameType::Uid, ntypes::UID),
            (NameType::X500Principal, ntypes::X500_PRINCIPAL),
            (NameType::SmtpName, ntypes::SMTP_NAME),
            (NameType::Enterprise, ntypes::ENTERPRISE),
        ];

        for (expected, value) in testcases {
            let bytes = value.to_der().unwrap();
            let decoded = Int32::from_der(&bytes).unwrap();
            let actual = NameType::try_from(decoded).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn encode_decode_for_name_typed_works_fine() {
        let testcases = vec![
            NameType::Principal,
            NameType::SrvInst,
            NameType::SrcHst,
            NameType::SrvXhst,
            NameType::Uid,
            NameType::X500Principal,
            NameType::SmtpName,
            NameType::Enterprise,
        ];

        for ntype in testcases {
            // The first way
            let bytes = ntype.as_bytes();
            let decoded = NameType::from_der(&bytes).unwrap();
            assert_eq!(ntype, decoded);

            // The second way
            let bytes = ntype.to_der().unwrap();
            let decoded = NameType::from_der(&bytes).unwrap();
            assert_eq!(ntype, decoded);
        }
    }

    #[test]
    fn address_type_should_provide_as_bytes_correctly() {
        let testcases = vec![
            (AddressType::IPv4, atypes::IPV4),
            (AddressType::Directional, atypes::DIRECTIONAL),
            (AddressType::ChaosNet, atypes::CHAOS_NET),
            (AddressType::Xns, atypes::XNS),
            (AddressType::Iso, atypes::ISO),
            (AddressType::DecnetPhaseIV, atypes::DECNET_PHASE_IV),
            (AddressType::AppletalkDDP, atypes::APPLETALK_DDP),
            (AddressType::Netbios, atypes::NETBIOS),
            (AddressType::IPv6, atypes::IPV6),
        ];

        for (atype, expected) in testcases {
            let bytes = atype.as_bytes();
            assert_eq!(bytes, expected.to_der().unwrap());
        }
    }

    #[test]
    fn address_type_should_panic_when_given_non_mapped_value() {
        let testcases = vec![-1, -9, i32::MIN];
        for test in testcases {
            let der_i32 = Int32::from_der(&test.to_der().unwrap()).unwrap();
            assert!(std::panic::catch_unwind(|| AddressType::try_from(der_i32).unwrap()).is_err());
        }
    }

    #[test]
    fn address_type_should_map_to_corres_enum_variants_when_given_correct_value() {
        let testcases = vec![
            (AddressType::IPv4, atypes::IPV4),
            (AddressType::Directional, atypes::DIRECTIONAL),
            (AddressType::ChaosNet, atypes::CHAOS_NET),
            (AddressType::Xns, atypes::XNS),
            (AddressType::Iso, atypes::ISO),
            (AddressType::DecnetPhaseIV, atypes::DECNET_PHASE_IV),
            (AddressType::AppletalkDDP, atypes::APPLETALK_DDP),
            (AddressType::Netbios, atypes::NETBIOS),
            (AddressType::IPv6, atypes::IPV6),
        ];

        for (expected, value) in testcases {
            let bytes = value.to_der().unwrap();
            let decoded = Int32::from_der(&bytes).unwrap();
            let actual = AddressType::try_from(decoded).unwrap();
            assert_eq!(expected, actual);
        }
    }
    
    #[test]
    fn encode_decode_for_address_type_works_fine() {
        let testcases = vec![
            AddressType::IPv4,
            AddressType::Directional,
            AddressType::ChaosNet,
            AddressType::Xns,
            AddressType::Iso,
            AddressType::DecnetPhaseIV,
            AddressType::AppletalkDDP,
            AddressType::Netbios,
            AddressType::IPv6,
        ];

        for atype in testcases {
            // The first way
            let bytes = atype.as_bytes();
            let decoded = AddressType::from_der(&bytes).unwrap();
            assert_eq!(atype, decoded);

            // The second way
            let bytes = atype.to_der().unwrap();
            let decoded = AddressType::from_der(&bytes).unwrap();
            assert_eq!(atype, decoded);
        }
    }
}
