use der::{Decode, DecodeValue, Encode, EncodeValue, FixedTag, Sequence, TagNumber};

use crate::basic::{
    application_tags, Int32, KerberosString, KerberosTime, Microseconds, OctetString,
    PrincipalName, Realm,
};

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

#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
struct KrbErrorMsgInner {
    #[asn1(context_specific = "0")]
    pvno: Int32,
    #[asn1(context_specific = "1")]
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
    error_code: Int32,
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

impl KrbErrorMsg {
    pub fn builder(
        stime: KerberosTime,
        susec: Microseconds,
        error_code: Int32,
        realm: Realm,
        sname: PrincipalName,
    ) -> KrbErrorMsgBuilder {
        KrbErrorMsgBuilder::new(stime, susec, error_code, realm, sname)
    }

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

pub struct KrbErrorMsgBuilder {
    stime: KerberosTime,
    susec: Microseconds,
    error_code: Int32,
    realm: Realm,
    sname: PrincipalName,
    crealm: Option<Realm>,
    ctime: Option<KerberosTime>,
    cusec: Option<Microseconds>,
    cname: Option<PrincipalName>,
    e_text: Option<KerberosString>,
    e_data: Option<OctetString>,
}

impl KrbErrorMsgBuilder {
    fn new(
        stime: KerberosTime,
        susec: Microseconds,
        error_code: Int32,
        realm: Realm,
        sname: PrincipalName,
    ) -> Self {
        Self {
            stime,
            susec,
            error_code,
            realm,
            sname,
            crealm: None,
            ctime: None,
            cusec: None,
            cname: None,
            e_text: None,
            e_data: None,
        }
    }

    pub fn build(self) -> KrbErrorMsg {
        let pvno = 5;
        let msg_type = 30;
        KrbErrorMsg(KrbErrorMsgInner {
            pvno,
            msg_type,
            ctime: self.ctime,
            cusec: self.cusec,
            stime: self.stime,
            susec: self.susec,
            error_code: self.error_code,
            crealm: self.crealm,
            cname: self.cname,
            realm: self.realm,
            sname: self.sname,
            e_text: self.e_text,
            e_data: self.e_data,
        })
    }

    pub fn crealm(mut self, crealm: Realm) -> Self {
        self.crealm = Some(crealm);
        self
    }

    pub fn ctime(mut self, ctime: KerberosTime) -> Self {
        self.ctime = Some(ctime);
        self
    }

    pub fn cusec(mut self, cusec: Microseconds) -> Self {
        self.cusec = Some(cusec);
        self
    }

    pub fn cname(mut self, cname: PrincipalName) -> Self {
        self.cname = Some(cname);
        self
    }

    pub fn e_text(mut self, e_text: KerberosString) -> Self {
        self.e_text = Some(e_text);
        self
    }

    pub fn e_data(mut self, e_data: OctetString) -> Self {
        self.e_data = Some(e_data);
        self
    }
}

impl From<Ecode> for Int32 {
    fn from(ecode: Ecode) -> Self {
        Int32::from(ecode as i32)
    }
}

impl From<Int32> for Ecode {
    fn from(value: Int32) -> Self {
        value.try_into().unwrap()
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Ecode {
    KDC_ERR_NONE = 0,                           // No error
    KDC_ERR_NAME_EXP = 1,                       // Client's entry in database has expired
    KDC_ERR_SERVICE_EXP = 2,                    // Server's entry in database has expired
    KDC_ERR_BAD_PVNO = 3,                       // Requested protocol version number not supported
    KDC_ERR_C_OLD_MAST_KVNO = 4,                // Client's key encrypted in old master key
    KDC_ERR_S_OLD_MAST_KVNO = 5,                // Server's key encrypted in old master key
    KDC_ERR_C_PRINCIPAL_UNKNOWN = 6,            // Client not found in Kerberos database
    KDC_ERR_S_PRINCIPAL_UNKNOWN = 7,            // Server not found in Kerberos database
    KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8,           // Multiple principal entries in database
    KDC_ERR_NULL_KEY = 9,                       // The client or server has a null key
    KDC_ERR_CANNOT_POSTDATE = 10,               // Ticket not eligible for postdating
    KDC_ERR_NEVER_VALID = 11,                   // Requested starttime is later than end time
    KDC_ERR_POLICY = 12,                        // KDC policy rejects request
    KDC_ERR_BADOPTION = 13,                     // KDC cannot accommodate requested option
    KDC_ERR_ETYPE_NOSUPP = 14,                  // KDC has no support for encryption type
    KDC_ERR_SUMTYPE_NOSUPP = 15,                // KDC has no support for checksum type
    KDC_ERR_PADATA_TYPE_NOSUPP = 16,            // KDC has no support for padata type
    KDC_ERR_TRTYPE_NOSUPP = 17,                 // KDC has no support for transited type
    KDC_ERR_CLIENT_REVOKED = 18,                // Client's credentials have been revoked
    KDC_ERR_SERVICE_REVOKED = 19,               // Credentials for server have been revoked
    KDC_ERR_TGT_REVOKED = 20,                   // TGT has been revoked
    KDC_ERR_CLIENT_NOTYET = 21,                 // Client not yet valid; try again later
    KDC_ERR_SERVICE_NOTYET = 22,                // Server not yet valid; try again later
    KDC_ERR_KEY_EXPIRED = 23,                   // Password has expired; change password to reset
    KDC_ERR_PREAUTH_FAILED = 24,                // Pre-authentication information was invalid
    KDC_ERR_PREAUTH_REQUIRED = 25,              // Additional pre-authentication required
    KDC_ERR_SERVER_NOMATCH = 26,                // Requested server and ticket don't match
    KDC_ERR_MUST_USE_USER2USER = 27,            // Server principal valid for user2user only
    KDC_ERR_PATH_NOT_ACCEPTED = 28,             // KDC Policy rejects transited path
    KDC_ERR_SVC_UNAVAILABLE = 29,               // A service is not available
    KRB_AP_ERR_BAD_INTEGRITY = 31,              // Integrity check on decrypted field failed
    KRB_AP_ERR_TKT_EXPIRED = 32,                // Ticket expired
    KRB_AP_ERR_TKT_NYV = 33,                    // Ticket not yet valid
    KRB_AP_ERR_REPEAT = 34,                     // Request is a replay
    KRB_AP_ERR_NOT_US = 35,                     // The ticket isn't for us
    KRB_AP_ERR_BADMATCH = 36,                   // Ticket and authenticator don't match
    KRB_AP_ERR_SKEW = 37,                       // Clock skew too great
    KRB_AP_ERR_BADADDR = 38,                    // Incorrect net address
    KRB_AP_ERR_BADVERSION = 39,                 // Protocol version mismatch
    KRB_AP_ERR_MSG_TYPE = 40,                   // Invalid msg type
    KRB_AP_ERR_MODIFIED = 41,                   // Message stream modified
    KRB_AP_ERR_BADORDER = 42,                   // Message out of order
    KRB_AP_ERR_BADKEYVER = 44,                  // Specified version of key is not available
    KRB_AP_ERR_NOKEY = 45,                      // Service key not available
    KRB_AP_ERR_MUT_FAIL = 46,                   // Mutual authentication failed
    KRB_AP_ERR_BADDIRECTION = 47,               // Incorrect message direction
    KRB_AP_ERR_METHOD = 48,                     // Alternative authentication method required
    KRB_AP_ERR_BADSEQ = 49,                     // Incorrect sequence number in message
    KRB_AP_ERR_INAPP_CKSUM = 50,                // Inappropriate type of checksum in message
    KRB_AP_PATH_NOT_ACCEPTED = 51,              // Policy rejects transited path
    KRB_ERR_RESPONSE_TOO_BIG = 52,              // Response too big for UDP; retry with TCP
    KRB_ERR_GENERIC = 60,                       // Generic error (description in e-text)
    KRB_ERR_FIELD_TOOLONG = 61,                 // Field is too long for this implementation
    KDC_ERROR_CLIENT_NOT_TRUSTED = 62,          // Reserved for PKINIT
    KDC_ERROR_KDC_NOT_TRUSTED = 63,             // Reserved for PKINIT
    KDC_ERROR_INVALID_SIG = 64,                 // Reserved for PKINIT
    KDC_ERR_KEY_TOO_WEAK = 65,                  // Reserved for PKINIT
    KDC_ERR_CERTIFICATE_MISMATCH = 66,          // Reserved for PKINIT
    KRB_AP_ERR_NO_TGT = 67,                     // No TGT available to validate USER-TO-USER
    KDC_ERR_WRONG_REALM = 68,                   // Reserved for future use
    KRB_AP_ERR_USER_TO_USER_REQUIRED = 69,      // Ticket must be for USER-TO-USER
    KDC_ERR_CANT_VERIFY_CERTIFICATE = 70,       // Reserved for PKINIT
    KDC_ERR_INVALID_CERTIFICATE = 71,           // Reserved for PKINIT
    KDC_ERR_REVOKED_CERTIFICATE = 72,           // Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73,     // Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74, // Reserved for PKINIT
    KDC_ERR_CLIENT_NAME_MISMATCH = 75,          // Reserved for PKINIT
    KDC_ERR_KDC_NAME_MISMATCH = 76,             // Reserved for PKINIT
}

#[cfg(test)]
mod test;
