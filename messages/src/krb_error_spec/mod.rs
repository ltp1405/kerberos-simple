use crate::back_to_enum;
use crate::basic::{
    application_tags, Int32, KerberosString, KerberosTime, Microseconds, OctetString,
    PrincipalName, Realm,
};
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Length, Sequence, Tag, TagNumber, Writer,
};
use derive_builder::{Builder, UninitializedFieldError};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct KrbErrorMsg(KrbErrorMsgInner);

impl EncodeValue for KrbErrorMsg {
    fn value_len(&self) -> der::Result<der::Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode(encoder)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for KrbErrorMsg {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let inner = KrbErrorMsgInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl FixedTag for KrbErrorMsg {
    const TAG: der::Tag = der::Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::KRB_ERROR),
    };
}

#[derive(Builder, Sequence, PartialEq, Eq, Clone, Debug)]
#[builder(setter(into), public, build_fn(skip), name = "KrbErrorMsgBuilder")]
struct KrbErrorMsgInner {
    #[asn1(context_specific = "0")]
    #[builder(setter(skip))]
    pvno: Int32,
    #[asn1(context_specific = "1")]
    #[builder(setter(skip))]
    msg_type: Int32,
    #[asn1(context_specific = "2", optional = "true")]
    ctime: Option<KerberosTime>,
    #[asn1(context_specific = "3", optional = "true")]
    cusec: Option<Microseconds>,
    #[asn1(context_specific = "4")]
    stime: KerberosTime,
    #[asn1(context_specific = "5")]
    susec: Microseconds,
    #[asn1(context_specific = "6")]
    error_code: Ecode,
    #[asn1(context_specific = "7", optional = "true")]
    crealm: Option<Realm>,
    #[asn1(context_specific = "8", optional = "true")]
    cname: Option<PrincipalName>,
    #[asn1(context_specific = "9")]
    realm: Realm, // service realm
    #[asn1(context_specific = "10")]
    sname: PrincipalName, // service name
    #[asn1(context_specific = "11", optional = "true")]
    e_text: Option<KerberosString>,
    #[asn1(context_specific = "12", optional = "true")]
    e_data: Option<OctetString>,
}

impl KrbErrorMsgBuilder {
    pub fn build(&self) -> Result<KrbErrorMsg, UninitializedFieldError> {
        Ok(KrbErrorMsg(KrbErrorMsgInner {
            pvno: 5,
            msg_type: application_tags::KRB_ERROR as Int32,
            ctime: self.ctime.flatten(),
            cusec: self.cusec.flatten(),
            stime: self.stime.ok_or(UninitializedFieldError::new("stime"))?,
            susec: self.susec.ok_or(UninitializedFieldError::new("susec"))?,
            error_code: self
                .error_code
                .ok_or(UninitializedFieldError::new("error_code"))?,
            crealm: self.clone().crealm.flatten(),
            cname: self.clone().cname.flatten(),
            realm: self
                .clone()
                .realm
                .ok_or(UninitializedFieldError::new("realm"))?,
            sname: self
                .clone()
                .sname
                .ok_or(UninitializedFieldError::new("sname"))?,
            e_text: self.clone().e_text.flatten(),
            e_data: self.clone().e_data.flatten(),
        }))
    }
}

impl KrbErrorMsg {
    pub fn pvno(&self) -> &Int32 {
        &self.0.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.0.msg_type
    }

    pub fn ctime(&self) -> Option<KerberosTime> {
        self.0.ctime
    }

    pub fn cusec(&self) -> Option<&Int32> {
        self.0.cusec.as_ref()
    }

    pub fn stime(&self) -> &KerberosTime {
        &self.0.stime
    }

    pub fn susec(&self) -> &Microseconds {
        &self.0.susec
    }

    pub fn error_code(&self) -> Ecode {
        self.0.error_code.into()
    }

    pub fn crealm(&self) -> Option<&KerberosString> {
        self.0.crealm.as_ref()
    }

    pub fn cname(&self) -> Option<&PrincipalName> {
        self.0.cname.as_ref()
    }

    pub fn realm(&self) -> &Realm {
        &self.0.realm
    }

    pub fn sname(&self) -> &PrincipalName {
        &self.0.sname
    }

    pub fn e_text(&self) -> Option<&KerberosString> {
        self.0.e_text.as_ref()
    }

    pub fn e_data(&self) -> Option<&OctetString> {
        self.0.e_data.as_ref()
    }
}

impl From<Ecode> for Int32 {
    fn from(ecode: Ecode) -> Self {
        ecode as i32
    }
}

impl FixedTag for Ecode {
    const TAG: Tag = Tag::Integer;
}

impl<'a> DecodeValue<'a> for Ecode {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let value = Int32::decode_value(reader, header)?;
        Ok(Self::try_from(value).expect("invalid Ecode"))
    }
}

impl EncodeValue for Ecode {
    fn value_len(&self) -> der::Result<Length> {
        Int32::from(*self).value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        Int32::from(*self).encode_value(encoder)
    }
}

back_to_enum! {
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub enum Ecode {
    /// No error
    KDC_ERR_NONE = 0,
    /// Client's entry in database has expired
    KDC_ERR_NAME_EXP = 1,
    /// Server's entry in database has expired
    KDC_ERR_SERVICE_EXP = 2,
    /// Requested protocol version number not supported
    KDC_ERR_BAD_PVNO = 3,
    /// Client's key encrypted in old master key
    KDC_ERR_C_OLD_MAST_KVNO = 4,
    /// Server's key encrypted in old master key
    KDC_ERR_S_OLD_MAST_KVNO = 5,
    /// Client not found in Kerberos database
    KDC_ERR_C_PRINCIPAL_UNKNOWN = 6,
    /// Server not found in Kerberos database
    KDC_ERR_S_PRINCIPAL_UNKNOWN = 7,
    /// Multiple principal entries in database
    KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8,
    /// The client or server has a null key
    KDC_ERR_NULL_KEY = 9,
    /// Ticket not eligible for postdating
    KDC_ERR_CANNOT_POSTDATE = 10,
    /// Requested starttime is later than end time
    KDC_ERR_NEVER_VALID = 11,
    /// KDC policy rejects request
    KDC_ERR_POLICY = 12,
    /// KDC cannot accommodate requested option
    KDC_ERR_BADOPTION = 13,
    /// KDC has no support for encryption type
    KDC_ERR_ETYPE_NOSUPP = 14,
    /// KDC has no support for checksum type
    KDC_ERR_SUMTYPE_NOSUPP = 15,
    /// KDC has no support for padata type
    KDC_ERR_PADATA_TYPE_NOSUPP = 16,
    /// KDC has no support for transited type
    KDC_ERR_TRTYPE_NOSUPP = 17,
    /// Client's credentials have been revoked
    KDC_ERR_CLIENT_REVOKED = 18,
    /// Credentials for server have been revoked
    KDC_ERR_SERVICE_REVOKED = 19,
    /// TGT has been revoked
    KDC_ERR_TGT_REVOKED = 20,
    /// Client not yet valid; try again later
    KDC_ERR_CLIENT_NOTYET = 21,
    /// Server not yet valid; try again later
    KDC_ERR_SERVICE_NOTYET = 22,
    /// Password has expired; change password to reset
    KDC_ERR_KEY_EXPIRED = 23,
    /// Pre-authentication information was invalid
    KDC_ERR_PREAUTH_FAILED = 24,
    /// Additional pre-authentication required
    KDC_ERR_PREAUTH_REQUIRED = 25,
    /// Requested server and ticket don't match
    KDC_ERR_SERVER_NOMATCH = 26,
    /// Server principal valid for user2user only
    KDC_ERR_MUST_USE_USER2USER = 27,
    /// KDC Policy rejects transited path
    KDC_ERR_PATH_NOT_ACCEPTED = 28,
    /// A service is not available
    KDC_ERR_SVC_UNAVAILABLE = 29,
    /// Integrity check on decrypted field failed
    KRB_AP_ERR_BAD_INTEGRITY = 31,
    /// Ticket expired
    KRB_AP_ERR_TKT_EXPIRED = 32,
    /// Ticket not yet valid
    KRB_AP_ERR_TKT_NYV = 33,
    /// Request is a replay
    KRB_AP_ERR_REPEAT = 34,
    /// The ticket isn't for us
    KRB_AP_ERR_NOT_US = 35,
    /// Ticket and authenticator don't match
    KRB_AP_ERR_BADMATCH = 36,
    /// Clock skew too great
    KRB_AP_ERR_SKEW = 37,
    /// Incorrect net address
    KRB_AP_ERR_BADADDR = 38,
    /// Protocol version mismatch
    KRB_AP_ERR_BADVERSION = 39,
    /// Invalid msg type
    KRB_AP_ERR_MSG_TYPE = 40,
    /// Message stream modified
    KRB_AP_ERR_MODIFIED = 41,
    /// Message out of order
    KRB_AP_ERR_BADORDER = 42,
    /// Specified version of key is not available
    KRB_AP_ERR_BADKEYVER = 44,
    /// Service key not available
    KRB_AP_ERR_NOKEY = 45,
    /// Mutual authentication failed
    KRB_AP_ERR_MUT_FAIL = 46,
    /// Incorrect message direction
    KRB_AP_ERR_BADDIRECTION = 47,
    /// Alternative authentication method required
    KRB_AP_ERR_METHOD = 48,
    /// Incorrect sequence number in message
    KRB_AP_ERR_BADSEQ = 49,
    /// Inappropriate type of checksum in message
    KRB_AP_ERR_INAPP_CKSUM = 50,
    /// Policy rejects transited path
    KRB_AP_PATH_NOT_ACCEPTED = 51,
    /// Response too big for UDP; retry with TCP
    KRB_ERR_RESPONSE_TOO_BIG = 52,
    /// Generic error (description in e-text)
    KRB_ERR_GENERIC = 60,
    /// Field is too long for this implementation
    KRB_ERR_FIELD_TOOLONG = 61,
    /// Reserved for PKINIT
    KDC_ERROR_CLIENT_NOT_TRUSTED = 62,
    /// Reserved for PKINIT
    KDC_ERROR_KDC_NOT_TRUSTED = 63,
    /// Reserved for PKINIT
    KDC_ERROR_INVALID_SIG = 64,
    /// Reserved for PKINIT
    KDC_ERR_KEY_TOO_WEAK = 65,
    /// Reserved for PKINIT
    KDC_ERR_CERTIFICATE_MISMATCH = 66,
    /// No TGT available to validate USER-TO-USER
    KRB_AP_ERR_NO_TGT = 67,
    /// Reserved for future use
    KDC_ERR_WRONG_REALM = 68,
    /// Ticket must be for USER-TO-USER
    KRB_AP_ERR_USER_TO_USER_REQUIRED = 69,
    /// Reserved for PKINIT
    KDC_ERR_CANT_VERIFY_CERTIFICATE = 70,
    /// Reserved for PKINIT
    KDC_ERR_INVALID_CERTIFICATE = 71,
    /// Reserved for PKINIT
    KDC_ERR_REVOKED_CERTIFICATE = 72,
    /// Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73,
    /// Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74,
    /// Reserved for PKINIT
    KDC_ERR_CLIENT_NAME_MISMATCH = 75,
    /// Reserved for PKINIT
    KDC_ERR_KDC_NAME_MISMATCH = 76,
}
}

#[cfg(test)]
mod test;
