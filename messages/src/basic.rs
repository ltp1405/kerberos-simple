use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use der::{
    self,
    asn1::{GeneralizedTime, Ia5String, OctetStringRef},
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
#[derive(Sequence, Debug, PartialEq, Eq, Clone)]
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
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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

#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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

    pub fn for_local_use(&self) -> Result<bool, &'static str> {
        self.for_registered_use().map(|r| !r)
    }

    pub fn for_registered_use(&self) -> Result<bool, &'static str> {
        let bytes = self
            .ad_type
            .to_der()
            .map_err(|_| "Could not encode AD type to DER bytes")?;
        let decoded =
            i32::from_der(&bytes).map_err(|_| "Could not decode AD type from DER bytes")?;
        Ok(decoded >= 0)
    }

    pub fn ad_type(&self) -> &Int32 {
        &self.ad_type
    }

    pub fn ad_data(&self) -> &OctetString {
        &self.ad_data
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ADRegisteredEntry<const N: usize = DEFAULT_LEN> {
    IfRelevant(AdIfRelevant<N>),
    KdcIssued(AdKdcIssued<N>),
    AndOr(AdAndOr<N>),
    MandatoryForKdc(AdMandatoryForKdc<N>),
}

impl<const N: usize> ADRegisteredEntry<N> {
    pub fn upgrade(entry: &ADEntry) -> Result<Self, String> {
        match entry.for_local_use() {
            Ok(ans) if ans => return Err("AD type is for local use".to_string()),
            Err(_) => {
                return Err(
                    "Could not determine if AD type is for local or registered use".to_string(),
                )
            }
            _ => {}
        }

        fn to_meaningful_error(ad_type: i32, element: &str, e: der::Error) -> String {
            format!(
                "Bytes representation of AD type {} is not valid to decode to {}. Error: {}",
                ad_type, element, e
            )
        }

        let ad_type = {
            let bytes = entry
                .ad_type
                .to_der()
                .map_err(|e| format!("Could not encode AD type to DER bytes. Error: {}", e))?;
            i32::from_der(&bytes)
                .map_err(|e| format!("Could not decode AD type from DER bytes. Error: {}", e))?
        };

        let octet_str_ref: OctetStringRef = (&entry.ad_data).into();

        let decoded_element = match ad_type {
            adtypes::AD_IF_RELEVANT => ADRegisteredEntry::IfRelevant(
                octet_str_ref
                    .decode_into::<AdIfRelevant<N>>()
                    .map_err(|e| to_meaningful_error(ad_type, "AdIfRelevant", e))?,
            ),
            adtypes::AD_KDC_ISSUED => ADRegisteredEntry::KdcIssued(
                octet_str_ref
                    .decode_into::<AdKdcIssued<N>>()
                    .map_err(|e| to_meaningful_error(ad_type, "AdKdcIssued", e))?,
            ),
            adtypes::AD_AND_OR => ADRegisteredEntry::AndOr(
                octet_str_ref
                    .decode_into::<AdAndOr<N>>()
                    .map_err(|e| to_meaningful_error(ad_type, "AdAndOr", e))?,
            ),
            adtypes::AD_MANDATORY_FOR_KDC => ADRegisteredEntry::MandatoryForKdc(
                octet_str_ref
                    .decode_into::<AdMandatoryForKdc<N>>()
                    .map_err(|e| to_meaningful_error(ad_type, "AdMandatoryForKdc", e))?,
            ),
            _ => return Err("Unsupported ad-type value. Please refer to RFC4120".to_string()),
        };

        Ok(decoded_element)
    }
}

// RFC4120 5.2.6.1
pub type AdIfRelevant<const N: usize = DEFAULT_LEN> = AuthorizationData<N>;

// RFC4120 5.2.6.2
#[derive(PartialEq, Eq, Clone, Debug)]
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

    pub fn i_realm(&self) -> Option<&Realm> {
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
        let i_realm = Option::<Realm>::decode(reader)?;
        let i_sname = Option::<PrincipalName<N>>::decode(reader)?;
        let elements = reader.decode()?;
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
#[derive(PartialEq, Eq, Clone, Debug)]
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
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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

    pub fn for_registered_use(&self) -> Result<bool, &'static str> {
        let bytes = self
            .padata_type
            .to_der()
            .map_err(|_| "Cannot encode padata_type")?;
        let decoded = i32::from_der(&bytes).map_err(|_| "Cannot decode padata_type")?;
        Ok(decoded >= 0)
    }

    pub fn for_unregistered_use(&self) -> Result<bool, &'static str> {
        self.for_registered_use().map(|b| !b)
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

impl<const N: usize> PaDataRegisteredType<N> {
    // Attempt to upgrade from the current PaData to a registered type.
    // If the PaData is not for registered use, an error is returned.
    // If the PaData is for registered use, but the type is not recognized, an error is returned.
    pub fn upgrade(pa_data: &PaData) -> Result<Self, String> {
        match pa_data.for_unregistered_use() {
            Ok(value) if value => return Err("PaData is not for registered use".to_string()),
            Err(_) => return Err("Cannot determine if PaData is for registered use".to_string()),
            _ => {}
        }

        fn to_meaningful_error(pa_type: i32, element: &str, e: der::Error) -> String {
            format!(
                "Bytes representation of PA type {} is not valid to decode to {}. Error: {}",
                pa_type, element, e
            )
        }

        let padata_type = {
            let bytes = pa_data
                .padata_type
                .to_der()
                .map_err(|_| "Cannot encode padata_type")?;
            i32::from_der(&bytes).map_err(|_| "Cannot decode padata_type")?
        };

        let octet_str_ref: OctetStringRef = (&pa_data.padata_value).into();

        let value = match padata_type {
            patypes::PA_TGS_REQ => todo!("Wait for the interface of AS-REP"),
            patypes::PA_ENC_TIMESTAMP => {
                let decoded = octet_str_ref.decode_into::<EncryptedData>().map_err(|e| {
                    to_meaningful_error(patypes::PA_ENC_TIMESTAMP, "EncryptedData", e)
                })?;
                PaDataRegisteredType::EncTimeStamp(decoded)
            }
            patypes::PA_PW_SALT => {
                let decoded = octet_str_ref
                    .decode_into::<OctetString>()
                    .map_err(|e| to_meaningful_error(patypes::PA_PW_SALT, "OctetString", e))?;
                PaDataRegisteredType::PwSalt(decoded)
            }
            patypes::PA_ETYPE_INFO => {
                let decoded = octet_str_ref
                    .decode_into::<ETypeInfo<N>>()
                    .map_err(|e| to_meaningful_error(patypes::PA_ETYPE_INFO, "ETYPE-INFO", e))?;
                PaDataRegisteredType::ETypeInfo(decoded)
            }
            patypes::PA_ETYPE_INFO2 => {
                let decoded = octet_str_ref
                    .decode_into::<ETypeInfo2<N>>()
                    .map_err(|e| to_meaningful_error(patypes::PA_ETYPE_INFO2, "ETYPE-INFO2", e))?;
                PaDataRegisteredType::ETypeInfo2(decoded)
            }
            _ => return Err(format!("Unknown PA type: {}", padata_type)),
        };

        Ok(value)
    }
}

// RFC4120 5.2.7.1
// The ciphertext (padata-value) consists
// of the PA-ENC-TS-ENC encoding, encrypted using the client's secret
// key and a key usage value of 1.
pub type PaEncTimestamp = EncryptedData;

// todo(phatalways_sleeping): implement TryFrom<EncryptedData> for PaEncTsEnc

// RFC4120 5.2.7.2
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct KerberosFlags {
    inner: BitSring,
}

impl KerberosFlags {
    pub fn builder() -> KerberosFlagsBuilder {
        KerberosFlagsBuilder::new()
    }

    pub fn is_set(&self, option: &KerberosFlagsOption) -> bool {
        let bit = option.to_u8() % 8;
        let idx = (option.to_u8() / 8) as usize;
        let bytes = self.inner.raw_bytes();
        bytes.get(idx).map_or(false, |byte| byte & (1 << bit) != 0)
    }

    // Get the vector of options that are set in the flags.
    pub fn options(&self) -> Vec<KerberosFlagsOption> {
        let mut options = Vec::new();
        let bytes = self.inner.raw_bytes();
        (0..bytes.len()).for_each(|i| {
            for j in 0..8 {
                if bytes[i] & (1 << j) != 0 {
                    if let Some(option) = KerberosFlagsOption::from_u8(i as u8 * 8 + j) {
                        options.push(option);
                    }
                }
            }
        });
        options
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

pub struct KerberosFlagsBuilder {
    inner: [u8; 4], // 4 bytes
}

impl KerberosFlagsBuilder {
    fn new() -> Self {
        Self { inner: [0; 4] }
    }

    pub fn build(self) -> Result<KerberosFlags, &'static str> {
        let inner = BitSring::from_bytes(&self.inner).map_err(|e| {
            eprintln!("Failed to build KerberosFlags: {}", e);
            "Invalid bits representation {:?}"
        })?;
        Ok(KerberosFlags { inner })
    }

    pub fn set_reserved(mut self) -> Self {
        self.inner[0] |= flags::RESERVED;
        self
    }

    pub fn set_forwardable(mut self) -> Self {
        self.inner[0] |= flags::FORWARDABLE;
        self
    }

    pub fn set_forwarded(mut self) -> Self {
        self.inner[0] |= flags::FORWARDED;
        self
    }

    pub fn set_proxiable(mut self) -> Self {
        self.inner[0] |= flags::PROXIABLE;
        self
    }

    pub fn set_proxy(mut self) -> Self {
        self.inner[0] |= flags::PROXY;
        self
    }

    pub fn set_may_postdate(mut self) -> Self {
        self.inner[0] |= flags::MAY_POSTDATE;
        self
    }

    pub fn set_postdated(mut self) -> Self {
        self.inner[0] |= flags::POSTDATED;
        self
    }

    pub fn set_invalid(mut self) -> Self {
        self.inner[0] |= flags::INVALID;
        self
    }

    pub fn set_renewable(mut self) -> Self {
        self.inner[1] |= flags::RENEWABLE;
        self
    }

    pub fn set_initial(mut self) -> Self {
        self.inner[1] |= flags::INITIAL;
        self
    }

    pub fn set_pre_authenticated(mut self) -> Self {
        self.inner[1] |= flags::PRE_AUTHENT;
        self
    }

    pub fn set_hw_authenticated(mut self) -> Self {
        self.inner[1] |= flags::HW_AUTHENT;
        self
    }

    pub fn set_transited_policy_checked(mut self) -> Self {
        self.inner[1] |= flags::TRANSITED_POLICY_CHECKED;
        self
    }

    pub fn set_ok_as_delegate(mut self) -> Self {
        self.inner[1] |= flags::OK_AS_DELEGATE;
        self
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum KerberosFlagsOption {
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
}

impl KerberosFlagsOption {
    fn to_u8(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::Forwardable => 1,
            Self::Forwarded => 2,
            Self::Proxiable => 3,
            Self::Proxy => 4,
            Self::MayPostdate => 5,
            Self::Postdated => 6,
            Self::Invalid => 7,
            Self::Renewable => 8,
            Self::Initial => 9,
            Self::PreAuthenticated => 10,
            Self::HWAuthenticated => 11,
            Self::TransitedPolicyChecked => 12,
            Self::OkAsDelegate => 13,
        }
    }

    fn from_u8(flag: u8) -> Option<Self> {
        match flag {
            0 => Some(Self::Reserved),
            1 => Some(Self::Forwardable),
            2 => Some(Self::Forwarded),
            3 => Some(Self::Proxiable),
            4 => Some(Self::Proxy),
            5 => Some(Self::MayPostdate),
            6 => Some(Self::Postdated),
            7 => Some(Self::Invalid),
            8 => Some(Self::Renewable),
            9 => Some(Self::Initial),
            10 => Some(Self::PreAuthenticated),
            11 => Some(Self::HWAuthenticated),
            12 => Some(Self::TransitedPolicyChecked),
            13 => Some(Self::OkAsDelegate),
            _ => None,
        }
    }
}

// RFC4120 5.2.9
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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
mod test;
