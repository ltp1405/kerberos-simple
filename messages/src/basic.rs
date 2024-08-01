use der::{
    self,
    asn1::{GeneralizedTime, Ia5String},
};

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
pub struct PrincipalName {}

// RFC4120 5.2.5
pub struct HostAddress {}

// RFC4120 5.2.5
pub struct HostAddresses {}

// RFC4120 5.2.6
pub struct AuthorizationData {}

// RFC4120 5.2.6.1
pub type AdIfRelevant = AuthorizationData;

// RFC4120 5.2.6.2
pub struct AdKdcIssued {}

// RFC4120 5.2.6.3
pub struct AdAndOr {}

// RFC4120 5.2.6.4
pub type AdMandatoryForKdc = AuthorizationData;

// RFC4120 5.2.7
pub struct PaData {}

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
pub struct Checksum {}

// RFC4120 5.2.9
pub struct EncryptionKey {}
