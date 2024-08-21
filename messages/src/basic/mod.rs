use std::time::{SystemTime, UNIX_EPOCH};

use der::{
    self,
    asn1::{GeneralizedTime, OctetStringRef},
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Writer,
};

pub use constants::flags; // Export flags from constants module for external use of KerberosFlags
pub(super) use constants::*;

pub mod constants;

pub type SequenceOf<T> = Vec<T>;
pub type OctetString = der::asn1::OctetString;
pub type BitString = der::asn1::BitString;

// RFC4120 5.2.4
pub type Int32 = i32;
// RFC4120 5.2.4
pub type UInt32 = u32;
// RFC4120 5.2.4
pub type Microseconds = i32;

// RFC4120 5.2.1
pub use kerberos_string::KerberosString;

// RFC4120 5.2.3
pub type KerberosTime = GeneralizedTime;

// RFC4120 5.2.2
pub type Realm = KerberosString;

// RFC4120 5.2.2
#[derive(Sequence, Debug, PartialEq, Eq, Clone)]
pub struct PrincipalName {
    #[asn1(context_specific = "0")]
    name_type: Int32,
    #[asn1(context_specific = "1")]
    // Most PrincipalNames will have only a few components (typically one or two).
    name_string: SequenceOf<KerberosString>,
}

impl PrincipalName {
    pub fn new<K: Into<SequenceOf<KerberosString>>>(
        nt_code: NameTypes,
        components: K,
    ) -> Result<Self, &'static str> {
        let name_string = components.into();

        if name_string.is_empty() {
            return Err("PrincipalName must have at least one component");
        }

        Ok(Self {
            name_type: nt_code as i32,
            name_string,
        })
    }

    pub fn name_type(&self) -> &Int32 {
        &self.name_type
    }

    pub fn has_name_type_of(&self, nt_code: NameTypes) -> bool {
        let bytes = (nt_code as i32)
            .to_der()
            .expect("This operation is always successful");
        let nt = Int32::from_der(&bytes).expect("This operation is always successful");
        self.name_type == nt
    }

    pub fn name_string(&self) -> &SequenceOf<KerberosString> {
        &self.name_string
    }
}

// RFC4120 5.2.5
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct HostAddress {
    #[asn1(context_specific = "0")]
    addr_type: Int32,
    #[asn1(context_specific = "1")]
    address: OctetString,
}

impl HostAddress {
    pub fn new<S: Into<OctetString>>(
        at_code: AddressTypes,
        address: S,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            addr_type: at_code as i32,
            address: address.into(),
        })
    }

    pub fn addr_type(&self) -> &Int32 {
        &self.addr_type
    }

    pub fn has_addr_type_of(&self, at_code: AddressTypes) -> bool {
        let bytes = (at_code as i32)
            .to_der()
            .expect("This operation is always successful");
        let at = Int32::from_der(&bytes).expect("This operation is always successful");
        self.addr_type == at
    }

    pub fn address(&self) -> &OctetString {
        &self.address
    }
}

// RFC4120 5.2.5
// HostAddresses is always used as an OPTIONAL field and should not be empty.
pub type HostAddresses = SequenceOf<HostAddress>;

// RFC4120 5.2.6
// AuthorizationData is always used as an OPTIONAL field and should not be empty.
pub type AuthorizationData = SequenceOf<ADEntry>;

#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct ADEntry {
    #[asn1(context_specific = "0")]
    ad_type: Int32, // All negative values are reserved for local use. Non-negative values are reserved for registered use.
    #[asn1(context_specific = "1")]
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

pub trait CipherText: Encode {
    fn to_cipher_text(&self) -> Result<OctetString, &'static str> {
        let bytes = self.to_der().map_err(|_| {
            "Could not encode the struct to DER bytes. Please check if all fields are set correctly"
        })?;
        let cipher_text = OctetString::new(bytes)
            .map_err(|_| "Could not create cipher text from the encoded DER bytes")?;
        Ok(cipher_text)
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ADRegisteredEntry {
    IfRelevant(AdIfRelevant),
    KdcIssued(AdKdcIssued),
    AndOr(AdAndOr),
    MandatoryForKdc(AdMandatoryForKdc),
}

impl ADRegisteredEntry {
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

        fn to_meaningful_error(
            ad_type: AuthorizationDataTypes,
            element: &str,
            e: der::Error,
        ) -> String {
            format!(
                "Bytes representation of AD type {:?} is not valid to decode to {}. Error: {}",
                ad_type, element, e
            )
        }

        let ad_type = AuthorizationDataTypes::try_from(entry.ad_type)
            .map_err(|e| format!("Invalid AD type: {}", e))?;

        let octet_str_ref: OctetStringRef = (&entry.ad_data).into();

        #[allow(unreachable_patterns)]
        let decoded_element = match ad_type {
            AuthorizationDataTypes::IfRelevant => ADRegisteredEntry::IfRelevant(
                octet_str_ref
                    .decode_into::<AdIfRelevant>()
                    .map_err(|e| to_meaningful_error(ad_type, "AdIfRelevant", e))?,
            ),
            AuthorizationDataTypes::KdcIssued => ADRegisteredEntry::KdcIssued(
                octet_str_ref
                    .decode_into::<AdKdcIssued>()
                    .map_err(|e| to_meaningful_error(ad_type, "AdKdcIssued", e))?,
            ),
            AuthorizationDataTypes::AndOr => ADRegisteredEntry::AndOr(
                octet_str_ref
                    .decode_into::<AdAndOr>()
                    .map_err(|e| to_meaningful_error(ad_type, "AdAndOr", e))?,
            ),
            AuthorizationDataTypes::MandatoryForKdc => ADRegisteredEntry::MandatoryForKdc(
                octet_str_ref
                    .decode_into::<AdMandatoryForKdc>()
                    .map_err(|e| to_meaningful_error(ad_type, "AdMandatoryForKdc", e))?,
            ),
            _ => return Err("Unsupported ad-type value. Please refer to RFC4120".to_string()),
        };

        Ok(decoded_element)
    }
}

// RFC4120 5.2.6.1
pub type AdIfRelevant = AuthorizationData;

impl CipherText for AdIfRelevant {}

// RFC4120 5.2.6.2
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct AdKdcIssued {
    #[asn1(context_specific = "0")]
    ad_checksum: Checksum,
    #[asn1(context_specific = "1", optional = "true")]
    i_realm: Option<Realm>,
    #[asn1(context_specific = "2", optional = "true")]
    i_sname: Option<PrincipalName>,
    #[asn1(context_specific = "3")]
    elements: AuthorizationData,
}

impl CipherText for AdKdcIssued {}

impl AdKdcIssued {
    pub fn new(
        ad_checksum: Checksum,
        i_realm: Option<Realm>,
        i_sname: Option<PrincipalName>,
        elements: AuthorizationData,
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

    pub fn i_sname(&self) -> Option<&PrincipalName> {
        self.i_sname.as_ref()
    }

    pub fn elements(&self) -> &AuthorizationData {
        &self.elements
    }
}

// RFC4120 5.2.6.3
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct AdAndOr {
    #[asn1(context_specific = "0")]
    condition_count: Int32,
    #[asn1(context_specific = "1")]
    elements: AuthorizationData,
}

impl CipherText for AdAndOr {}

impl AdAndOr {
    pub fn new(condition_count: Int32, elements: AuthorizationData) -> Self {
        Self {
            condition_count,
            elements,
        }
    }

    pub fn condition_count(&self) -> &Int32 {
        &self.condition_count
    }

    pub fn elements(&self) -> &AuthorizationData {
        &self.elements
    }
}

// RFC4120 5.2.6.4
pub type AdMandatoryForKdc = AuthorizationData;

// RFC4120 5.2.7
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct PaData {
    // Negative values of padata-type are reserved for unregistered use;
    // non-negative values are used for a registered interpretation of the element type.
    #[asn1(context_specific = "1")]
    padata_type: Int32,
    #[asn1(context_specific = "2")]
    padata_value: OctetString,
}

impl PaData {
    pub fn new<T: Into<Int32>, V: Into<OctetString>>(padata_type: T, padata_value: V) -> Self {
        Self {
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

pub enum PaDataRegisteredType {
    TgsReq,                       // DER encoding of AP-REQ
    EncTimeStamp(PaEncTimestamp), // DER encoding of PA-ENC-TIMESTAMP
    // The padata-value for this pre-authentication type contains the salt
    // for the string-to-key to be used by the client to obtain the key for
    // decrypting the encrypted part of an AS-REP message.
    PwSalt(OctetString),    // salt (not ASN.1 encoded)
    ETypeInfo(ETypeInfo),   // DER encoding of ETYPE-INFO
    ETypeInfo2(ETypeInfo2), // DER encoding of ETYPE-INFO2
}

impl PaDataRegisteredType {
    // Attempt to upgrade from the current PaData to a registered type.
    // If the PaData is not for registered use, an error is returned.
    // If the PaData is for registered use, but the type is not recognized, an error is returned.
    pub fn upgrade(pa_data: &PaData) -> Result<Self, String> {
        match pa_data.for_unregistered_use() {
            Ok(value) if value => return Err("PaData is not for registered use".to_string()),
            Err(_) => return Err("Cannot determine if PaData is for registered use".to_string()),
            _ => {}
        }

        fn to_meaningful_error(pa_type: PaDataTypes, element: &str, e: der::Error) -> String {
            format!(
                "Bytes representation of PA type {:?} is not valid to decode to {}. Error: {}",
                pa_type, element, e
            )
        }

        let padata_type = PaDataTypes::try_from(pa_data.padata_type)
            .map_err(|e| format!("Invalid PA type: {}", e))?;

        let octet_str_ref: OctetStringRef = (&pa_data.padata_value).into();

        #[allow(unreachable_patterns)]
        let value = match padata_type {
            PaDataTypes::PaTgsReq => todo!("Wait for the interface of AS-REP"),
            PaDataTypes::PaEncTimestamp => {
                let decoded = octet_str_ref
                    .decode_into::<EncryptedData>()
                    .map_err(|e| to_meaningful_error(padata_type, "EncryptedData", e))?;
                PaDataRegisteredType::EncTimeStamp(decoded)
            }
            PaDataTypes::PaPwSalt => {
                let decoded = octet_str_ref
                    .decode_into::<OctetString>()
                    .map_err(|e| to_meaningful_error(padata_type, "OctetString", e))?;
                PaDataRegisteredType::PwSalt(decoded)
            }
            PaDataTypes::PaEtypeInfo => {
                let decoded = octet_str_ref
                    .decode_into::<ETypeInfo>()
                    .map_err(|e| to_meaningful_error(padata_type, "ETYPE-INFO", e))?;
                PaDataRegisteredType::ETypeInfo(decoded)
            }
            PaDataTypes::PaEtypeInfo2 => {
                let decoded = octet_str_ref
                    .decode_into::<ETypeInfo2>()
                    .map_err(|e| to_meaningful_error(padata_type, "ETYPE-INFO2", e))?;
                PaDataRegisteredType::ETypeInfo2(decoded)
            }
            _ => return Err(format!("Unknown PA type: {:?}", padata_type)),
        };

        Ok(value)
    }
}

// RFC4120 5.2.7.1
// The ciphertext (padata-value) consists
// of the PA-ENC-TS-ENC encoding, encrypted using the client's secret
// key and a key usage value of 1.
pub type PaEncTimestamp = EncryptedData;

impl CipherText for PaEncTimestamp {}

// todo(phatalways_sleeping): implement TryFrom<EncryptedData> for PaEncTsEnc

// RFC4120 5.2.7.2
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct PaEncTsEnc {
    #[asn1(context_specific = "0")]
    pa_timestamp: KerberosTime, // client's time
    #[asn1(context_specific = "1", optional = "true")]
    pa_usec: Option<Microseconds>, // client's microseconds
}

impl CipherText for PaEncTsEnc {}

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
        let microseconds = 120;
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
    #[asn1(context_specific = "0")]
    etype: Int32,
    #[asn1(context_specific = "1", optional = "true")]
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
pub type ETypeInfo = SequenceOf<ETypeInfoEntry>;

impl CipherText for ETypeInfo {}

// RFC4120 5.2.7.5
// If ETYPE-INFO2 is sent in an AS-REP, there shall be exactly one
// ETYPE-INFO2-ENTRY, and its etype shall match that of the enc-part in
// the AS-REP.
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct ETypeInfo2Entry {
    #[asn1(context_specific = "0")]
    etype: Int32,
    #[asn1(context_specific = "1", optional = "true")]
    salt: Option<KerberosString>,
    #[asn1(context_specific = "2", optional = "true")]
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

    pub fn salt(&self) -> Option<&KerberosString> {
        self.salt.as_ref()
    }

    pub fn s2kparams(&self) -> Option<&OctetString> {
        self.s2kparams.as_ref()
    }
}

// RFC4120 5.2.7.5
pub type ETypeInfo2 = SequenceOf<ETypeInfo2Entry>;

impl CipherText for ETypeInfo2 {}

// RFC4120 5.2.8
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct KerberosFlags {
    inner: BitString,
}

impl KerberosFlags {
    pub fn builder() -> KerberosFlagsBuilder {
        KerberosFlagsBuilder::new()
    }

    pub fn is_set(&self, bit_pos: usize) -> bool {
        let bit = (bit_pos % 8) as u8;
        let shift = 7 - bit;
        let idx = bit_pos / 8;
        let bytes = self.inner.raw_bytes();
        bytes
            .get(idx)
            .map_or(false, |byte| byte & (1 << shift) != 0)
    }
}

impl FixedTag for KerberosFlags {
    const TAG: der::Tag = der::Tag::BitString;
}

impl EncodeValue for KerberosFlags {
    fn value_len(&self) -> der::Result<Length> {
        self.inner.value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.inner.encode_value(encoder)
    }
}

impl<'a> DecodeValue<'a> for KerberosFlags {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let inner = BitString::decode_value(reader, header)?;
        Ok(Self { inner })
    }
}

pub struct KerberosFlagsBuilder {
    inner: *mut [u8], // array of bytes
    consumed: bool,
}

impl KerberosFlagsBuilder {
    fn new() -> Self {
        Self {
            inner: Box::into_raw(Box::new([0; 4])),
            consumed: false,
        }
    }

    pub fn len(mut self, len: usize) -> Result<Self, &'static str> {
        unsafe {
            if len < 4 {
                return Err("Length must be at least 4 bytes");
            }
            if len == self.inner.len() {
                return Ok(self);
            }
            let new_inner = {
                let (old_inner, mut new_inner) = (Box::from_raw(self.inner), vec![0; len]);
                if old_inner.len() > len {
                    new_inner.copy_from_slice(&old_inner[..len]);
                } else {
                    new_inner[..old_inner.len()].copy_from_slice(&old_inner);
                }
                new_inner
            };
            self.inner = Box::into_raw(new_inner.into_boxed_slice());
            Ok(self)
        }
    }

    pub fn set(self, bit_pos: usize) -> Self {
        unsafe {
            if bit_pos >= self.inner.len() * 8 {
                return self;
            }
            let byte_pos = bit_pos / 8;
            let bit_pos = bit_pos % 8;
            let shift_bits = 7 - bit_pos;
            (*self.inner)[byte_pos] |= 1 << shift_bits;
            self
        }
    }

    pub fn build(mut self) -> Result<KerberosFlags, &'static str> {
        self.consumed = true;
        let bytes = unsafe { Box::from_raw(self.inner) };
        let inner = BitString::from_bytes(&bytes).map_err(|e| {
            eprintln!("Failed to build KerberosFlags: {}", e);
            "Invalid bits representation {:?}"
        })?;
        Ok(KerberosFlags { inner })
    }
}

impl Drop for KerberosFlagsBuilder {
    fn drop(&mut self) {
        if !self.consumed {
            unsafe {
                drop(Box::from_raw(self.inner));
            }
        }
    }
}

// RFC4120 5.2.9
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct EncryptedData {
    #[asn1(context_specific = "0")]
    etype: Int32,
    #[asn1(context_specific = "1", optional = "true")]
    kvno: Option<UInt32>,
    #[asn1(context_specific = "2")]
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

    pub fn kvno(&self) -> Option<&UInt32> {
        self.kvno.as_ref()
    }

    pub fn cipher(&self) -> &OctetString {
        &self.cipher
    }
}

// RFC4120 5.2.9
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct EncryptionKey {
    #[asn1(context_specific = "0")]
    keytype: Int32,
    #[asn1(context_specific = "1")]
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
    #[asn1(context_specific = "0")]
    cksumtype: Int32,
    #[asn1(context_specific = "1")]
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
mod kerberos_string;
