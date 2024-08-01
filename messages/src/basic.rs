use std::{marker::PhantomData, ops::Deref};

use convertable_derive::Convertable;
use der::{
    self,
    asn1::{GeneralizedTime, Ia5String},
    Decode, DecodeValue, Encode, EncodeValue, Sequence,
};

const DEFAULT_LEN: usize = 255;

pub type SequenceOf<T, const U: usize> = der::asn1::SequenceOf<T, U>;
pub type OctetString = der::asn1::OctetString;
pub type BitSring = der::asn1::BitString;

// RFC4120 5.2.4
pub type Int32 = der::asn1::Int;
// RFC4120 5.2.4
pub type UInt32 = der::asn1::Int;
// RFC4120 5.2.4
pub type Microseconds = der::asn1::Int;

// RFC4120 5.2.1
pub type KerberosString = Ia5String;

// RFC4120 5.2.3
pub type KerberosTime = GeneralizedTime;

// RFC4120 5.2.2
pub type Realm = KerberosString;

// RFC4120 5.2.2
#[derive(Sequence)]
pub struct PrincipalName<const N: usize = 2> {
    name_type: Int32,
    // Most PrincipalNames will have only a few components (typically one or two).
    pub name_string: SequenceOf<KerberosString, N>,
}

impl<const N: usize> PrincipalName<N> {
    pub fn new<K: Into<SequenceOf<KerberosString, N>>>(
        name_type: PredefinedNameType,
        components: K,
    ) -> Result<Self, &'static str> {
        let name_type = name_type.into();

        let name_string = components.into();

        if name_string.is_empty() {
            return Err("PrincipalName must have at least one component");
        }

        Ok(Self {
            name_type,
            name_string,
        })
    }

    pub fn get_name_type(&self) -> PredefinedNameType {
        self.name_type.as_bytes().into()
    }
}

// RFC4120 6.2
#[derive(Debug, PartialEq, Eq, Convertable)]
pub enum PredefinedNameType {
    #[convert(0x00)]
    Unknown,
    #[convert(0x01)]
    Principal,
    #[convert(0x02)]
    SrvInst,
    #[convert(0x03)]
    SrcHst,
    #[convert(0x04)]
    SrvXhst,
    #[convert(0x05)]
    Uid,
    #[convert(0x06)]
    X500Principal,
    #[convert(0x07)]
    SmtpName,
    #[convert(0x0A)]
    Enterprise,
}

// RFC4120 5.2.5
#[derive(Sequence)]
pub struct HostAddress {
    addr_type: Int32,
    pub address: OctetString,
}

impl HostAddress {
    pub fn new<S: Into<OctetString>>(addr_type: PredefinedAddressType, address: S) -> Self {
        Self {
            addr_type: addr_type.into(),
            address: address.into(),
        }
    }

    pub fn get_addr_type(&self) -> PredefinedAddressType {
        self.addr_type.as_bytes().into()
    }
}

// RFC4120 7.5.3
#[derive(Debug, PartialEq, Eq, Convertable)]
pub enum PredefinedAddressType {
    #[convert(0x02)]
    Ipv4,
    #[convert(0x03)]
    Directional,
    #[convert(0x05)]
    ChaosNet,
    #[convert(0x06)]
    Xns,
    #[convert(0x07)]
    Iso,
    #[convert(0x0C)]
    DecnetPhaseIV,
    #[convert(0x10)]
    AppleTalkDDP,
    #[convert(0x14)]
    NetBios,
    #[convert(0x18)]
    Ipv6,
}

// RFC4120 5.2.5
// HostAddresses is always used as an OPTIONAL field and should not be empty.
pub struct HostAddresses<const N: usize> {
    inner: SequenceOf<HostAddress, N>,
}

impl<const N: usize> HostAddresses<N> {
    pub fn new(host_addresses: [HostAddress; N]) -> Option<Self> {
        if host_addresses.is_empty() {
            return None;
        }
        Some(Self {
            inner: {
                let mut inner = SequenceOf::new();
                for host_address in host_addresses {
                    inner
                        .add(host_address)
                        .expect("Cannot add HostAddress to HostAddresses");
                }
                inner
            },
        })
    }
}

impl<const N: usize> Deref for HostAddresses<N> {
    type Target = SequenceOf<HostAddress, N>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// RFC4120 5.2.6
// AuthorizationData is always used as an OPTIONAL field and should not be empty.
pub struct AuthorizationData<const N: usize = DEFAULT_LEN> {
    inner: Option<SequenceOf<ADEntry, N>>,
}

impl<'a, const N: usize> Decode<'a> for AuthorizationData<N> {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let inner = decoder.decode()?;
        Ok(Self { inner })
    }
}

impl<'a, const N: usize> DecodeValue<'a> for AuthorizationData<N> {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let inner = reader.decode()?;
        Ok(Self { inner })
    }
}

impl<const N: usize> EncodeValue for AuthorizationData<N> {
    fn value_len(&self) -> der::Result<der::Length> {
        self.inner
            .as_ref()
            .map_or(Ok(der::Length::ZERO), |inner| inner.value_len())
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.inner
            .as_ref()
            .map_or(Ok(()), |inner| inner.encode(encoder))
    }
}

impl<const N: usize> AuthorizationData<N> {
    pub fn new(entries: [ADEntry; N]) -> Self {
        let inner = if entries.is_empty() {
            None
        } else {
            Some({
                let mut inner = SequenceOf::new();
                for ad_entry in entries {
                    inner
                        .add(ad_entry)
                        .expect("Cannot add ADEntry to AuthorizationData");
                }
                inner
            })
        };
        Self { inner }
    }

    pub fn iter(&self) -> impl Iterator<Item = &ADEntry> {
        self.inner
            .as_ref()
            .into_iter()
            .flat_map(|inner| inner.iter())
    }
}

#[derive(Sequence)]
pub struct ADEntry {
    pub ad_type: Int32, // All negative values are reserved for local use. Non-negative values are reserved for registered use.
    pub ad_data: OctetString,
}

impl TryFrom<ADEntry> for ADElement {
    type Error = &'static str;

    fn try_from(entry: ADEntry) -> Result<Self, Self::Error> {
        let ad_type: PredefinedADType = entry.ad_type.as_bytes().into();
        let err_msg = "Invalid AD type";
        let bytes = entry.ad_data.as_bytes();

        let decoded_element = match ad_type {
            PredefinedADType::IfRelevant => {
                ADElement::IfRelevant(AdIfRelevant::from_der(bytes).map_err(|_| err_msg)?)
            }
            PredefinedADType::KdcIssued => {
                ADElement::KdcIssued(AdKdcIssued::from_der(bytes).map_err(|_| err_msg)?)
            }
            PredefinedADType::AndOr => {
                ADElement::AndOr(AdAndOr::from_der(bytes).map_err(|_| err_msg)?)
            }
            PredefinedADType::MandatoryForKdc => {
                ADElement::MandatoryForKdc(AdMandatoryForKdc::from_der(bytes).map_err(|_| err_msg)?)
            }
        };

        Ok(decoded_element)
    }
}

#[derive(Debug, PartialEq, Eq, Convertable)]
pub enum PredefinedADType {
    #[convert(0x01)]
    IfRelevant,
    #[convert(0x04)]
    KdcIssued,
    #[convert(0x05)]
    AndOr,
    #[convert(0x08)]
    MandatoryForKdc,
}

pub enum ADElement {
    IfRelevant(AdIfRelevant),
    KdcIssued(AdKdcIssued),
    AndOr(AdAndOr),
    MandatoryForKdc(AdMandatoryForKdc),
}

// RFC4120 5.2.6.1
pub type AdIfRelevant<const N: usize = DEFAULT_LEN> = AuthorizationData<N>;

// RFC4120 5.2.6.2
pub struct AdKdcIssued<const N: usize = DEFAULT_LEN> {
    pub ad_checksum: Checksum,
    pub i_realm: Option<Realm>,
    pub i_sname: Option<PrincipalName>,
    pub elements: AuthorizationData<N>,
}

impl<'a, const N: usize> DecodeValue<'a> for AdKdcIssued<N> {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let ad_checksum = reader.decode()?;
        let i_realm = reader.decode()?;
        let i_sname = reader.decode()?;
        let elements = AuthorizationData::decode_value(reader, header)?;
        Ok(Self {
            ad_checksum,
            i_realm,
            i_sname,
            elements,
        })
    }
}

impl<const N: usize> EncodeValue for AdKdcIssued<N> {
    fn value_len(&self) -> der::Result<der::Length> {
        self.ad_checksum.encoded_len()?
            + self.i_realm.encoded_len()?
            + self.i_sname.encoded_len()?
            + self.elements.value_len()?
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.ad_checksum.encode(encoder)?;
        self.i_realm.encode(encoder)?;
        self.i_sname.encode(encoder)?;
        self.elements.encode_value(encoder)?;
        Ok(())
    }
}

impl<'a, const N: usize> Sequence<'a> for AdKdcIssued<N> {}

// RFC4120 5.2.6.3
pub struct AdAndOr<const N: usize = DEFAULT_LEN> {
    pub condition_count: Int32,
    pub elements: AuthorizationData<N>,
}

impl<'a, const N: usize> DecodeValue<'a> for AdAndOr<N> {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let condition_count = reader.decode()?;
        let elements = AuthorizationData::decode_value(reader, header)?;
        Ok(Self {
            condition_count,
            elements,
        })
    }
}

impl<const N: usize> EncodeValue for AdAndOr<N> {
    fn value_len(&self) -> der::Result<der::Length> {
        self.condition_count.encoded_len()? + self.elements.value_len()?
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.condition_count.encode(encoder)?;
        self.elements.encode_value(encoder)?;
        Ok(())
    }
}

impl<'a, const N: usize> Sequence<'a> for AdAndOr<N> {}

// RFC4120 5.2.6.4
pub type AdMandatoryForKdc<const N: usize = DEFAULT_LEN> = AuthorizationData<N>;

// RFC4120 5.2.7
#[derive(Sequence)]
pub struct PaData {
    phantom: PhantomData<Int32>, // NOTE: first tag is [1], not [0]
    // Negative values of padata-type are reserved for unregistered use;
    // non-negative values are used for a registered interpretation of the element type.
    padata_type: Int32,
    padata_value: OctetString,
}

impl PaData {
    pub fn new<T: Into<Int32>, V: Into<OctetString>>(padata_type: T, padata_value: V) -> Self {
        Self {
            phantom: PhantomData,
            padata_type: padata_type.into(),
            padata_value: padata_value.into(),
        }
    }

    pub fn get_padata_type(&self) -> PredefinedPaDataType {
        self.padata_type.as_bytes().into()
    }
}

#[derive(PartialEq, Eq, Convertable)]
pub enum PredefinedPaDataType {
    #[convert(0x01)]
    PaTgsReq, // DER encoding of AP-REQ
    #[convert(0x02)]
    PaEncTimeStamp, // DER encoding of PA-ENC-TIMESTAMP
    #[convert(0x03)]
    PaPwSalt, // salt (not ASN.1 encoded)
    #[convert(0x0B)]
    PaETypeInfo, // DER encoding of ETYPE-INFO
    #[convert(0x13)]
    PaETypeInfo2, // DER encoding of ETYPE-INFO2
}

// RFC4120 5.2.7.1
pub type PaEncTimestamp = EncryptedData;

// RFC4120 5.2.7.2
pub struct PaEncTsEnc {}

// RFC4120 5.2.7.4
pub struct ETypeInfoEntry {}

// RFC4120 5.2.7.4
pub struct ETypeInfo {}

// RFC4120 5.2.7.5
pub struct ETypeInfo2Entry {}

// RFC4120 5.2.7.5
pub struct ETypeInfo2 {}

// RFC4120 5.2.8
pub struct KerberosFlags {}

// RFC4120 5.2.9
pub struct EncryptedData {}

// RFC4120 5.2.9
#[derive(Sequence)]
pub struct Checksum {
    cksumtype: Int32,
    checksum: OctetString,
}

// RFC4120 5.2.9
pub struct EncryptionKey {}

#[cfg(test)]
mod test {
    use crate::basic::{
        Int32, PredefinedAddressType, PrincipalName,
        SequenceOf,
    };

    use super::{KerberosString, PredefinedNameType};

    ////////////////////////// PrincipalName //////////////////////////

    fn init_components(size: usize) -> SequenceOf<KerberosString, 2> {
        let mut components = SequenceOf::new();
        for i in 0..size {
            let input = format!("test{}", i);
            components
                .add(KerberosString::new(&input).unwrap())
                .expect("Cannot add component");
        }
        components
    }

    #[test]
    fn principal_name_should_accept_valid_name_type() {
        let name_type = PredefinedNameType::Principal;
        let components = init_components(1);
        let principal_name = PrincipalName::new(name_type, components);
        assert!(principal_name.is_ok());
    }

    #[test]
    fn principal_name_should_have_at_least_one_component() {
        let name_type = PredefinedNameType::Principal;
        let components = SequenceOf::new();
        let principal_name = PrincipalName::<2>::new(name_type, components);
        assert!(principal_name.is_err());
    }

    #[test]
    fn no_panic_when_using_predefined_name_type() {
        let name_type = PredefinedNameType::Principal;
        let components = init_components(2);
        let principal_name =
            PrincipalName::new(name_type, components).expect("Cannot create PrincipalName");
        assert_eq!(
            principal_name.get_name_type(),
            PredefinedNameType::Principal
        );
    }

    ////////////////////////// HostAddress //////////////////////////
    #[test]
    fn predefined_address_type_should_return_correct_value() {
        let testcases = vec![
            (PredefinedAddressType::Ipv4, [0x02]),
            (PredefinedAddressType::Directional, [0x03]),
            (PredefinedAddressType::ChaosNet, [0x05]),
            (PredefinedAddressType::Xns, [0x06]),
            (PredefinedAddressType::Iso, [0x07]),
            (PredefinedAddressType::DecnetPhaseIV, [0x0C]),
            (PredefinedAddressType::AppleTalkDDP, [0x10]),
            (PredefinedAddressType::NetBios, [0x14]),
            (PredefinedAddressType::Ipv6, [0x18]),
        ];
        for (addr_type, expected_bytes) in testcases {
            let addr_type_bytes = Int32::from(addr_type);
            assert_eq!(addr_type_bytes.as_bytes(), &expected_bytes);
        }
    }

    #[test]
    fn predefined_address_type_should_return_correct_enum() {
        let testcases = vec![
            (PredefinedAddressType::Ipv4, [0x02]),
            (PredefinedAddressType::Directional, [0x03]),
            (PredefinedAddressType::ChaosNet, [0x05]),
            (PredefinedAddressType::Xns, [0x06]),
            (PredefinedAddressType::Iso, [0x07]),
            (PredefinedAddressType::DecnetPhaseIV, [0x0C]),
            (PredefinedAddressType::AppleTalkDDP, [0x10]),
            (PredefinedAddressType::NetBios, [0x14]),
            (PredefinedAddressType::Ipv6, [0x18]),
        ];
        for (expected_addr_type, addr_type_bytes) in testcases {
            let addr_type =
                PredefinedAddressType::from(Int32::new(&addr_type_bytes).unwrap().as_bytes());
            assert_eq!(addr_type, expected_addr_type);
        }
    }

    ///////////////////////// PaData //////////////////////////
}
