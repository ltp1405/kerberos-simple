use std::{
    marker::PhantomData,
    ops::Deref,
    time::{SystemTime, UNIX_EPOCH},
};

use der::{
    self,
    asn1::{GeneralizedTime, Ia5String},
    Decode, DecodeValue, Encode, EncodeValue, Sequence,
};

pub use constants::*;
use predefined_values::{AddressType, NameType};

mod constants;
mod predefined_values;

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
pub struct PrincipalName<const N: usize = DEFAULT_PRINCIPAL_COMPONENTS_LEN> {
    name_type: NameType,
    // Most PrincipalNames will have only a few components (typically one or two).
    name_string: SequenceOf<KerberosString, N>,
}

impl<const N: usize> PrincipalName<N> {
    pub fn new<K: Into<SequenceOf<KerberosString, N>>>(
        name_type: NameType,
        components: K,
    ) -> Result<Self, &'static str> {
        let name_string = components.into();

        if name_string.is_empty() {
            return Err("PrincipalName must have at least one component");
        }

        Ok(Self {
            name_type,
            name_string,
        })
    }

    pub fn name_type(&self) -> NameType {
        self.name_type
    }

    pub fn name_string(&self) -> &SequenceOf<KerberosString, N> {
        &self.name_string
    }
}

// RFC4120 5.2.5
#[derive(Sequence)]
pub struct HostAddress {
    addr_type: AddressType,
    address: OctetString,
}

impl HostAddress {
    pub fn new<S: Into<OctetString>>(addr_type: AddressType, address: S) -> Self {
        Self {
            addr_type,
            address: address.into(),
        }
    }

    pub fn addr_type(&self) -> AddressType {
        self.addr_type
    }

    pub fn address(&self) -> &OctetString {
        &self.address
    }
}

// RFC4120 5.2.5
// HostAddresses is always used as an OPTIONAL field and should not be empty.
pub type HostAddresses<const N: usize> = SequenceOf<HostAddress, N>;

// RFC4120 5.2.6
// AuthorizationData is always used as an OPTIONAL field and should not be empty.
pub type AuthorizationData<const N: usize = DEFAULT_LEN> = SequenceOf<ADEntry, N>;

#[derive(Sequence)]
pub struct ADEntry {
    ad_type: Int32, // All negative values are reserved for local use. Non-negative values are reserved for registered use.
    ad_data: OctetString,
}

impl ADEntry {
    pub fn new<A: Into<Int32>, S: Into<OctetString>>(ad_type: A, ad_data: S) -> Self {
        Self {
            ad_type: ad_type.into(),
            ad_data: ad_data.into(),
        }
    }

    pub fn for_local_use(&self) -> bool {
        !self.for_registered_use()
    }

    pub fn for_registered_use(&self) -> bool {
        let decoded =
            i32::from_der(self.ad_type.as_bytes()).expect("Could not decode bytes to i32");
        decoded >= 0
    }

    pub fn ad_type(&self) -> &Int32 {
        &self.ad_type
    }

    pub fn ad_data(&self) -> &OctetString {
        &self.ad_data
    }
}

impl TryFrom<ADEntry> for ADRegisteredEntry {
    type Error = String;

    fn try_from(entry: ADEntry) -> Result<Self, Self::Error> {
        if entry.for_local_use() {
            return Err("Local AD type is not supported".to_owned());
        }

        fn to_meaningful_error(ad_type: &[u8], element: &str, e: der::Error) -> String {
            format!(
                "Bytes representation of AD type {} is not valid to decode to {}. Error: {}",
                String::from_utf8_lossy(ad_type),
                element,
                e
            )
        }

        let ad_type = entry.ad_type.as_bytes();

        let bytes = entry.ad_data.as_bytes();

        let decoded_element = match ad_type {
            adtypes::AD_IF_RELEVANT => ADRegisteredEntry::IfRelevant(
                AdIfRelevant::from_der(bytes)
                    .map_err(|e| to_meaningful_error(ad_type, "AdIfRelevant", e))?,
            ),
            adtypes::AD_KDC_ISSUED => ADRegisteredEntry::KdcIssued(Box::new(
                AdKdcIssued::from_der(bytes)
                    .map_err(|e| to_meaningful_error(ad_type, "AdKdcIssued", e))?,
            )),
            adtypes::AD_AND_OR => ADRegisteredEntry::AndOr(
                AdAndOr::from_der(bytes).map_err(|e| to_meaningful_error(ad_type, "AdAndOr", e))?,
            ),
            adtypes::AD_MANDATORY_FOR_KDC => ADRegisteredEntry::MandatoryForKdc(
                AdMandatoryForKdc::from_der(bytes)
                    .map_err(|e| to_meaningful_error(ad_type, "AdMandatoryForKdc", e))?,
            ),
            _ => panic!("This should not happen. Local AD type is short-circuited"),
        };

        Ok(decoded_element)
    }
}

pub enum ADRegisteredEntry {
    IfRelevant(AdIfRelevant),
    KdcIssued(Box<AdKdcIssued>), // Boxing since AdKdcIssued is extremely large compared to other AD types
    AndOr(AdAndOr),
    MandatoryForKdc(AdMandatoryForKdc),
}

// RFC4120 5.2.6.1
pub type AdIfRelevant<const N: usize = DEFAULT_LEN> = AuthorizationData<N>;

// RFC4120 5.2.6.2
pub struct AdKdcIssued<const N: usize = DEFAULT_LEN> {
    ad_checksum: Checksum,
    i_realm: Option<Realm>,
    i_sname: Option<PrincipalName<N>>,
    elements: AuthorizationData<N>,
}

impl<const N: usize> AdKdcIssued<N> {
    pub fn new(
        ad_checksum: Checksum,
        i_realm: Option<Realm>,
        i_sname: Option<PrincipalName<N>>,
        elements: AuthorizationData<N>,
    ) -> Self {
        Self {
            ad_checksum,
            i_realm,
            i_sname,
            elements,
        }
    }

    pub fn ad_checksum(&self) -> &Checksum {
        &self.ad_checksum
    }

    pub fn i_realm(&self) -> Option<&Ia5String> {
        self.i_realm.as_ref()
    }

    pub fn i_sname(&self) -> Option<&PrincipalName<N>> {
        self.i_sname.as_ref()
    }

    pub fn elements(&self) -> &AuthorizationData<N> {
        &self.elements
    }
}

impl<'a, const N: usize> DecodeValue<'a> for AdKdcIssued<N> {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let ad_checksum = reader.decode()?;
        let i_realm = reader.decode()?;
        let i_sname = reader.decode()?;
        let elements = AuthorizationData::decode(reader)?;
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
            + self.elements.encoded_len()?
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.ad_checksum.encode(encoder)?;
        self.i_realm.encode(encoder)?;
        self.i_sname.encode(encoder)?;
        self.elements.encode(encoder)?;
        Ok(())
    }
}

impl<'a, const N: usize> Sequence<'a> for AdKdcIssued<N> {}

// RFC4120 5.2.6.3
pub struct AdAndOr<const N: usize = DEFAULT_LEN> {
    condition_count: Int32,
    elements: AuthorizationData<N>,
}

impl<const N: usize> AdAndOr<N> {
    pub fn new(condition_count: Int32, elements: AuthorizationData<N>) -> Self {
        Self {
            condition_count,
            elements,
        }
    }

    pub fn condition_count(&self) -> &Int32 {
        &self.condition_count
    }

    pub fn elements(&self) -> &AuthorizationData<N> {
        &self.elements
    }
}

impl<'a, const N: usize> DecodeValue<'a> for AdAndOr<N> {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let condition_count = reader.decode()?;
        let elements = AuthorizationData::decode(reader)?;
        Ok(Self {
            condition_count,
            elements,
        })
    }
}

impl<const N: usize> EncodeValue for AdAndOr<N> {
    fn value_len(&self) -> der::Result<der::Length> {
        self.condition_count.encoded_len()? + self.elements.encoded_len()?
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.condition_count.encode(encoder)?;
        self.elements.encode(encoder)?;
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

    pub fn for_registered_use(&self) -> bool {
        let decoded = i32::from_der(self.padata_type.as_bytes()).expect("padata_type is not Int32");
        decoded >= 0
    }

    pub fn for_unregistered_use(&self) -> bool {
        !self.for_registered_use()
    }
}

impl<const N: usize> TryFrom<PaData> for PaDataRegisteredType<N> {
    type Error = String;

    fn try_from(pa_data: PaData) -> Result<Self, Self::Error> {
        if pa_data.for_unregistered_use() {
            return Err("PaData is not for registered use".to_string());
        }

        fn to_meaningful_error(pa_type: &[u8], element: &str, e: der::Error) -> String {
            format!(
                "Bytes representation of PA type {} is not valid to decode to {}. Error: {}",
                String::from_utf8_lossy(pa_type),
                element,
                e
            )
        }

        let value = match pa_data.padata_type.as_bytes() {
            patypes::PA_TGS_REQ => todo!("Wait for the interface of AS-REP"),
            patypes::PA_ENC_TIMESTAMP => {
                let decoded =
                    EncryptedData::from_der(pa_data.padata_value.as_bytes()).map_err(|e| {
                        to_meaningful_error(patypes::PA_ENC_TIMESTAMP, "EncryptedData", e)
                    })?;
                PaDataRegisteredType::EncTimeStamp(decoded)
            }
            patypes::PA_PW_SALT => PaDataRegisteredType::PwSalt(pa_data.padata_value),
            patypes::PA_ETYPE_INFO => {
                let decoded = ETypeInfo::from_der(pa_data.padata_value.as_bytes())
                    .map_err(|e| to_meaningful_error(patypes::PA_ETYPE_INFO, "ETYPE-INFO", e))?;
                PaDataRegisteredType::ETypeInfo(decoded)
            }
            patypes::PA_ETYPE_INFO2 => {
                let decoded = ETypeInfo2::from_der(pa_data.padata_value.as_bytes())
                    .map_err(|e| to_meaningful_error(patypes::PA_ETYPE_INFO2, "ETYPE-INFO2", e))?;
                PaDataRegisteredType::ETypeInfo2(decoded)
            }
            _ => panic!("Cannot happen"),
        };

        Ok(value)
    }
}

pub enum PaDataRegisteredType<const N: usize = DEFAULT_AS_REP_ENTRIES_LEN> {
    TgsReq,                       // DER encoding of AP-REQ
    EncTimeStamp(PaEncTimestamp), // DER encoding of PA-ENC-TIMESTAMP
    // The padata-value for this pre-authentication type contains the salt
    // for the string-to-key to be used by the client to obtain the key for
    // decrypting the encrypted part of an AS-REP message.
    PwSalt(OctetString),       // salt (not ASN.1 encoded)
    ETypeInfo(ETypeInfo<N>),   // DER encoding of ETYPE-INFO
    ETypeInfo2(ETypeInfo2<N>), // DER encoding of ETYPE-INFO2
}

// RFC4120 5.2.7.1
// The ciphertext (padata-value) consists
// of the PA-ENC-TS-ENC encoding, encrypted using the client's secret
// key and a key usage value of 1.
pub type PaEncTimestamp = EncryptedData;

// todo(phatalways_sleeping): implement TryFrom<EncryptedData> for PaEncTsEnc

// RFC4120 5.2.7.2
#[derive(Sequence)]
pub struct PaEncTsEnc {
    pa_timestamp: KerberosTime,    // client's time
    pa_usec: Option<Microseconds>, // client's microseconds
}

impl PaEncTsEnc {
    pub fn new<T: Into<KerberosTime>, U: Into<Option<Microseconds>>>(
        pa_timestamp: T,
        pa_usec: U,
    ) -> Self {
        Self {
            pa_timestamp: pa_timestamp.into(),
            pa_usec: pa_usec.into(),
        }
    }

    // This function is used to initialize Self with the current time.
    pub fn now() -> Self {
        let now = SystemTime::now();
        let since_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
        let kerberos_time =
            KerberosTime::from_unix_duration(since_epoch).expect("Invalid KerberosTime");
        let microseconds = Microseconds::new(&since_epoch.subsec_micros().to_der().unwrap())
            .expect("Invalid microseconds");
        Self::new(kerberos_time, Some(microseconds))
    }

    pub fn pa_timestamp(&self) -> GeneralizedTime {
        self.pa_timestamp
    }

    pub fn pa_usec(&self) -> Option<&Microseconds> {
        self.pa_usec.as_ref()
    }
}

// RFC4120 5.2.7.4
#[derive(Sequence)]
pub struct ETypeInfoEntry {
    etype: Int32,
    salt: Option<OctetString>,
}

impl ETypeInfoEntry {
    pub fn new<T: Into<Int32>, U: Into<Option<OctetString>>>(etype: T, salt: U) -> Self {
        Self {
            etype: etype.into(),
            salt: salt.into(),
        }
    }

    pub fn etype(&self) -> &Int32 {
        &self.etype
    }

    pub fn salt(&self) -> Option<&OctetString> {
        self.salt.as_ref()
    }
}

// RFC4120 5.2.7.4
pub type ETypeInfo<const N: usize = DEFAULT_AS_REP_ENTRIES_LEN> = SequenceOf<ETypeInfoEntry, N>;

// RFC4120 5.2.7.5
// If ETYPE-INFO2 is sent in an AS-REP, there shall be exactly one
// ETYPE-INFO2-ENTRY, and its etype shall match that of the enc-part in
// the AS-REP.
#[derive(Sequence)]
pub struct ETypeInfo2Entry {
    etype: Int32,
    salt: Option<KerberosString>,
    s2kparams: Option<OctetString>,
}

impl ETypeInfo2Entry {
    pub fn new<T: Into<Int32>, U: Into<Option<KerberosString>>, V: Into<Option<OctetString>>>(
        etype: T,
        salt: U,
        s2kparams: V,
    ) -> Self {
        Self {
            etype: etype.into(),
            salt: salt.into(),
            s2kparams: s2kparams.into(),
        }
    }

    pub fn etype(&self) -> &Int32 {
        &self.etype
    }

    pub fn salt(&self) -> Option<&Ia5String> {
        self.salt.as_ref()
    }

    pub fn s2kparams(&self) -> Option<&OctetString> {
        self.s2kparams.as_ref()
    }
}

// RFC4120 5.2.7.5
pub type ETypeInfo2<const N: usize = DEFAULT_AS_REP_ENTRIES_LEN> = SequenceOf<ETypeInfo2Entry, N>;

// RFC4120 5.2.8
pub struct KerberosFlags {
    inner: BitSring,
}

pub enum KerberosFlagsKind {
    Reserved,
    Forwardable,
    Forwarded,
    Proxiable,
    Proxy,
    MayPostdate,
    Postdated,
    Invalid,
    Renewable,
    Initial,
    PreAuthenticated,
    HWAuthenticated,
    TransitedPolicyChecked,
    OkAsDelegate,
    Other,
}

impl KerberosFlags {
    pub fn kind(&self) -> KerberosFlagsKind {
        let bytes = self
            .inner
            .as_bytes()
            .expect("TryFrom<&[u8] forces BitString to be at least 32 bits long");
        match &bytes[..4] {
            // only the first 4 bytes are used (32 bits)
            flags::RESERVED => KerberosFlagsKind::Reserved,
            flags::FORWARDABLE => KerberosFlagsKind::Forwardable,
            flags::FORWARDED => KerberosFlagsKind::Forwarded,
            flags::PROXIABLE => KerberosFlagsKind::Proxiable,
            flags::PROXY => KerberosFlagsKind::Proxy,
            flags::MAY_POSTDATE => KerberosFlagsKind::MayPostdate,
            flags::POSTDATED => KerberosFlagsKind::Postdated,
            flags::INVALID => KerberosFlagsKind::Invalid,
            flags::RENEWABLE => KerberosFlagsKind::Renewable,
            flags::INITIAL => KerberosFlagsKind::Initial,
            flags::PRE_AUTHENT => KerberosFlagsKind::PreAuthenticated,
            flags::HW_AUTHENT => KerberosFlagsKind::HWAuthenticated,
            flags::TRANSITED_POLICY_CHECKED => KerberosFlagsKind::TransitedPolicyChecked,
            flags::OK_AS_DELEGATE => KerberosFlagsKind::OkAsDelegate,
            _ => KerberosFlagsKind::Other,
        }
    }
}

impl KerberosFlags {
    pub fn reserve() -> Self {
        Self::try_from(flags::RESERVED).expect("Cannot fail")
    }

    pub fn forwardable() -> Self {
        Self::try_from(flags::FORWARDABLE).expect("Cannot fail")
    }

    pub fn forwarded() -> Self {
        Self::try_from(flags::FORWARDED).expect("Cannot fail")
    }

    pub fn proxiable() -> Self {
        Self::try_from(flags::PROXIABLE).expect("Cannot fail")
    }

    pub fn proxy() -> Self {
        Self::try_from(flags::PROXY).expect("Cannot fail")
    }

    pub fn may_postdate() -> Self {
        Self::try_from(flags::MAY_POSTDATE).expect("Cannot fail")
    }

    pub fn postdated() -> Self {
        Self::try_from(flags::POSTDATED).expect("Cannot fail")
    }

    pub fn invalid() -> Self {
        Self::try_from(flags::INVALID).expect("Cannot fail")
    }

    pub fn renewable() -> Self {
        Self::try_from(flags::RENEWABLE).expect("Cannot fail")
    }

    pub fn initial() -> Self {
        Self::try_from(flags::INITIAL).expect("Cannot fail")
    }

    pub fn pre_authent() -> Self {
        Self::try_from(flags::PRE_AUTHENT).expect("Cannot fail")
    }

    pub fn hw_authent() -> Self {
        Self::try_from(flags::HW_AUTHENT).expect("Cannot fail")
    }

    pub fn transited_policy_checked() -> Self {
        Self::try_from(flags::TRANSITED_POLICY_CHECKED).expect("Cannot fail")
    }

    pub fn ok_as_delegate() -> Self {
        Self::try_from(flags::OK_AS_DELEGATE).expect("Cannot fail")
    }
}

impl Encode for KerberosFlags {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.inner.encoded_len()
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.inner.encode(encoder)
    }
}

impl<'a> Decode<'a> for KerberosFlags {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let inner = BitSring::decode(decoder)?;
        Ok(Self { inner })
    }
}

impl TryFrom<&[u8]> for KerberosFlags {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 4 {
            return Err("KerberosFlags's bit string must be at least 32 bits long");
        }
        let inner = BitSring::from_bytes(bytes).map_err(|_| "Error parsing bit string")?;
        Ok(Self { inner })
    }
}

impl Deref for KerberosFlags {
    type Target = BitSring;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// RFC4120 5.2.9
#[derive(Sequence)]
pub struct EncryptedData {
    etype: Int32,
    kvno: Option<UInt32>,
    cipher: OctetString,
}

impl EncryptedData {
    pub fn new<T: Into<Int32>, U: Into<Option<UInt32>>, V: Into<OctetString>>(
        etype: T,
        kvno: U,
        cipher: V,
    ) -> Self {
        Self {
            etype: etype.into(),
            kvno: kvno.into(),
            cipher: cipher.into(),
        }
    }

    pub fn etype(&self) -> &Int32 {
        &self.etype
    }

    pub fn kvno(&self) -> Option<&Int32> {
        self.kvno.as_ref()
    }

    pub fn cipher(&self) -> &OctetString {
        &self.cipher
    }
}

// RFC4120 5.2.9
#[derive(Sequence)]
pub struct EncryptionKey {
    keytype: Int32,
    keyvalue: OctetString,
}

impl EncryptionKey {
    pub fn new<T: Into<Int32>, U: Into<OctetString>>(keytype: T, keyvalue: U) -> Self {
        Self {
            keytype: keytype.into(),
            keyvalue: keyvalue.into(),
        }
    }

    pub fn keytype(&self) -> &Int32 {
        &self.keytype
    }

    pub fn keyvalue(&self) -> &OctetString {
        &self.keyvalue
    }
}

// RFC4120 5.2.9
#[derive(Sequence)]
pub struct Checksum {
    cksumtype: Int32,
    checksum: OctetString,
}

impl Checksum {
    pub fn new<T: Into<Int32>, U: Into<OctetString>>(cksumtype: T, checksum: U) -> Self {
        Self {
            cksumtype: cksumtype.into(),
            checksum: checksum.into(),
        }
    }

    pub fn cksumtype(&self) -> &Int32 {
        &self.cksumtype
    }

    pub fn checksum(&self) -> &OctetString {
        &self.checksum
    }
}

#[cfg(test)]
mod test {
    use crate::basic::{
        predefined_values::{AddressType, NameType},
        HostAddress, PrincipalName, SequenceOf,
    };

    use super::{HostAddresses, KerberosString, OctetString};

    ////////////////////////// PrincipalName //////////////////////////
    fn init_kerberos_string_len_1() -> SequenceOf<KerberosString, 1> {
        let mut kerberos_strings = SequenceOf::new();
        kerberos_strings
            .add(KerberosString::new("test").unwrap())
            .unwrap();
        kerberos_strings
    }

    fn init_kerberos_string_len_2() -> SequenceOf<KerberosString, 2> {
        let mut kerberos_strings = SequenceOf::new();
        for _ in 0..2 {
            kerberos_strings
                .add(KerberosString::new("test").unwrap())
                .unwrap();
        }
        kerberos_strings
    }

    #[test]
    fn principal_name_works_fine_with_appropriate_kerberos_string() {
        let testcases = vec![
            (NameType::Unknown, init_kerberos_string_len_2()),
            (NameType::SmtpName, init_kerberos_string_len_2()),
        ];

        for (expected_name_type, name_string) in testcases {
            let principal_name = PrincipalName::new(expected_name_type, name_string.clone());
            assert!(principal_name.is_ok());
            let principal_name = principal_name.unwrap();
            assert_eq!(principal_name.name_type(), expected_name_type);
            assert_eq!(principal_name.name_string(), &name_string);
        }

        let testcases = vec![
            (NameType::SrcHst, init_kerberos_string_len_1()),
            (NameType::X500Principal, init_kerberos_string_len_1()),
        ];

        for (expected_name_type, name_string) in testcases {
            let principal_name = PrincipalName::new(expected_name_type, name_string.clone());
            assert!(principal_name.is_ok());
            let principal_name = principal_name.unwrap();
            assert_eq!(principal_name.name_type(), expected_name_type);
            assert_eq!(principal_name.name_string(), &name_string);
        }
    }

    ////////////////////////// HostAddress //////////////////////////
    fn init_random_octet_string() -> OctetString {
        OctetString::new(vec![1, 2, 3, 4]).unwrap()
    }

    #[test]
    fn host_address_works_fine() {
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
        for address_type in testcases {
            let host_address = HostAddress::new(address_type, init_random_octet_string());
            assert_eq!(host_address.addr_type(), address_type);
            assert_eq!(host_address.address(), &init_random_octet_string());
        }
    }

    #[test]
    fn init_host_addresses_with_non_zero_length() {
        let provided = [
            HostAddress::new(AddressType::IPv4, init_random_octet_string()),
            HostAddress::new(AddressType::IPv6, init_random_octet_string()),
            HostAddress::new(AddressType::Directional, init_random_octet_string()),
            HostAddress::new(AddressType::ChaosNet, init_random_octet_string()),
        ];

        let addresses = HostAddresses::<4>::new(provided);

        assert!(addresses.is_some());
    }

    #[test]
    fn init_host_addresses_with_zero_length() {
        let provided = [];

        let addresses = HostAddresses::<0>::new(provided);

        assert!(addresses.is_none());
    }

    ///////////////////////// PaData //////////////////////////
}
