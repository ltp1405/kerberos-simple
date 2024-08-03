use der::{Decode, Encode, EncodeValue, FixedTag, TagNumber};

use crate::basic::{
    application_tags, Int32, KerberosString, KerberosTime, Microseconds, OctetString,
    PrincipalName, Realm,
};

pub struct KrbErrorMsg {
    pvno: Int32,
    msg_type: Int32,
    ctime: Option<KerberosTime>,
    cusec: Option<Microseconds>,
    stime: KerberosTime,
    susec: Microseconds,
    error_code: Int32,
    crealm: Option<Realm>,
    cname: Option<PrincipalName>,
    realm: Realm,         // service realm
    sname: PrincipalName, // service name
    e_text: Option<KerberosString>,
    e_data: Option<OctetString>,
}

impl EncodeValue for KrbErrorMsg {
    fn value_len(&self) -> der::Result<der::Length> {
        self.pvno.value_len()?
            + self.msg_type.value_len()?
            + self.ctime.encoded_len()?
            + self.cusec.encoded_len()?
            + self.stime.value_len()?
            + self.susec.value_len()?
            + self.error_code.value_len()?
            + self.crealm.encoded_len()?
            + self.cname.encoded_len()?
            + self.realm.value_len()?
            + self.sname.value_len()?
            + self.e_text.encoded_len()?
            + self.e_data.encoded_len()?
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.pvno.encode(encoder)?;
        self.msg_type.encode(encoder)?;
        self.ctime.encode(encoder)?;
        self.cusec.encode(encoder)?;
        self.stime.encode(encoder)?;
        self.susec.encode(encoder)?;
        self.error_code.encode(encoder)?;
        self.crealm.encode(encoder)?;
        self.cname.encode(encoder)?;
        self.realm.encode(encoder)?;
        self.sname.encode(encoder)?;
        self.e_text.encode(encoder)?;
        self.e_data.encode(encoder)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for KrbErrorMsg {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let pvno = Int32::decode(decoder)?;
        let msg_type = Int32::decode(decoder)?;
        let ctime = Option::<KerberosTime>::decode(decoder)?;
        let cusec = Option::<Microseconds>::decode(decoder)?;
        let stime = KerberosTime::decode(decoder)?;
        let susec = Microseconds::decode(decoder)?;
        let error_code = Int32::decode(decoder)?;
        let crealm = Option::<Realm>::decode(decoder)?;
        let cname = Option::<PrincipalName>::decode(decoder)?;
        let realm = Realm::decode(decoder)?;
        let sname = PrincipalName::decode(decoder)?;
        let e_text = Option::<KerberosString>::decode(decoder)?;
        let e_data = Option::<OctetString>::decode(decoder)?;
        Ok(Self {
            pvno,
            msg_type,
            ctime,
            cusec,
            stime,
            susec,
            error_code,
            crealm,
            cname,
            realm,
            sname,
            e_text,
            e_data,
        })
    }
}

impl FixedTag for KrbErrorMsg {
    const TAG: der::Tag = der::Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::KRB_ERROR),
    };
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
        &self.pvno
    }

    pub fn msg_type(&self) -> &Int32 {
        &self.msg_type
    }

    pub fn ctime(&self) -> Option<KerberosTime> {
        self.ctime
    }

    pub fn cusec(&self) -> Option<&Int32> {
        self.cusec.as_ref()
    }

    pub fn stime(&self) -> KerberosTime {
        self.stime
    }

    pub fn susec(&self) -> &Microseconds {
        &self.susec
    }

    pub fn error_code(&self) -> &Int32 {
        &self.error_code
    }

    pub fn crealm(&self) -> Option<&KerberosString> {
        self.crealm.as_ref()
    }

    pub fn cname(&self) -> Option<&PrincipalName> {
        self.cname.as_ref()
    }

    pub fn realm(&self) -> &str {
        self.realm.as_ref()
    }

    pub fn sname(&self) -> &PrincipalName {
        &self.sname
    }

    pub fn e_text(&self) -> Option<&KerberosString> {
        self.e_text.as_ref()
    }

    pub fn e_data(&self) -> Option<&OctetString> {
        self.e_data.as_ref()
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
        let pvno = {
            let bytes = 5.to_der().expect("pvno");
            Int32::new(&bytes).expect("pvno")
        };
        let msg_type = {
            let bytes = 30.to_der().expect("msg_type");
            Int32::new(&bytes).expect("msg_type")
        };
        KrbErrorMsg {
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
        }
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

pub mod ecodes {
    pub const KDC_ERR_NONE: i32 = 0; // No error
    pub const KDC_ERR_NAME_EXP: i32 = 1; // Client's entry in database has expired
    pub const KDC_ERR_SERVICE_EXP: i32 = 2; // Server's entry in database has expired
    pub const KDC_ERR_BAD_PVNO: i32 = 3; // Requested protocol version number not supported
    pub const KDC_ERR_C_OLD_MAST_KVNO: i32 = 4; // Client's key encrypted in old master key
    pub const KDC_ERR_S_OLD_MAST_KVNO: i32 = 5; // Server's key encrypted in old master key
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6; // Client not found in Kerberos database
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7; // Server not found in Kerberos database
    pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: i32 = 8; // Multiple principal entries in database
    pub const KDC_ERR_NULL_KEY: i32 = 9; // The client or server has a null key
    pub const KDC_ERR_CANNOT_POSTDATE: i32 = 10; // Ticket not eligible for postdating
    pub const KDC_ERR_NEVER_VALID: i32 = 11; // Requested starttime is later than end time
    pub const KDC_ERR_POLICY: i32 = 12; // KDC policy rejects request
    pub const KDC_ERR_BADOPTION: i32 = 13; // KDC cannot accommodate requested option
    pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14; // KDC has no support for encryption type
    pub const KDC_ERR_SUMTYPE_NOSUPP: i32 = 15; // KDC has no support for checksum type
    pub const KDC_ERR_PADATA_TYPE_NOSUPP: i32 = 16; // KDC has no support for padata type
    pub const KDC_ERR_TRTYPE_NOSUPP: i32 = 17; // KDC has no support for transited type
    pub const KDC_ERR_CLIENT_REVOKED: i32 = 18; // Client's credentials have been revoked
    pub const KDC_ERR_SERVICE_REVOKED: i32 = 19; // Credentials for server have been revoked
    pub const KDC_ERR_TGT_REVOKED: i32 = 20; // TGT has been revoked
    pub const KDC_ERR_CLIENT_NOTYET: i32 = 21; // Client not yet valid; try again later
    pub const KDC_ERR_SERVICE_NOTYET: i32 = 22; // Server not yet valid; try again later
    pub const KDC_ERR_KEY_EXPIRED: i32 = 23; // Password has expired; change password to reset
    pub const KDC_ERR_PREAUTH_FAILED: i32 = 24; // Pre-authentication information was invalid
    pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25; // Additional pre-authentication required
    pub const KDC_ERR_SERVER_NOMATCH: i32 = 26; // Requested server and ticket don't match
    pub const KDC_ERR_MUST_USE_USER2USER: i32 = 27; // Server principal valid for user2user only
    pub const KDC_ERR_PATH_NOT_ACCEPTED: i32 = 28; // KDC Policy rejects transited path
    pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29; // A service is not available
    pub const KRB_AP_ERR_BAD_INTEGRITY: i32 = 31; // Integrity check on decrypted field failed
    pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32; // Ticket expired
    pub const KRB_AP_ERR_TKT_NYV: i32 = 33; // Ticket not yet valid
    pub const KRB_AP_ERR_REPEAT: i32 = 34; // Request is a replay
    pub const KRB_AP_ERR_NOT_US: i32 = 35; // The ticket isn't for us
    pub const KRB_AP_ERR_BADMATCH: i32 = 36; // Ticket and authenticator don't match
    pub const KRB_AP_ERR_SKEW: i32 = 37; // Clock skew too great
    pub const KRB_AP_ERR_BADADDR: i32 = 38; // Incorrect net address
    pub const KRB_AP_ERR_BADVERSION: i32 = 39; // Protocol version mismatch
    pub const KRB_AP_ERR_MSG_TYPE: i32 = 40; // Invalid msg type
    pub const KRB_AP_ERR_MODIFIED: i32 = 41; // Message stream modified
    pub const KRB_AP_ERR_BADORDER: i32 = 42; // Message out of order
    pub const KRB_AP_ERR_BADKEYVER: i32 = 44; // Specified version of key is not available
    pub const KRB_AP_ERR_NOKEY: i32 = 45; // Service key not available
    pub const KRB_AP_ERR_MUT_FAIL: i32 = 46; // Mutual authentication failed
    pub const KRB_AP_ERR_BADDIRECTION: i32 = 47; // Incorrect message direction
    pub const KRB_AP_ERR_METHOD: i32 = 48; // Alternative authentication method required
    pub const KRB_AP_ERR_BADSEQ: i32 = 49; // Incorrect sequence number in message
    pub const KRB_AP_ERR_INAPP_CKSUM: i32 = 50; // Inappropriate type of checksum in message
    pub const KRB_AP_PATH_NOT_ACCEPTED: i32 = 51; // Policy rejects transited path
    pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52; // Response too big for UDP; retry with TCP
    pub const KRB_ERR_GENERIC: i32 = 60; // Generic error (description in e-text)
    pub const KRB_ERR_FIELD_TOOLONG: i32 = 61; // Field is too long for this implementation
    pub const KDC_ERROR_CLIENT_NOT_TRUSTED: i32 = 62; // Reserved for PKINIT
    pub const KDC_ERROR_KDC_NOT_TRUSTED: i32 = 63; // Reserved for PKINIT
    pub const KDC_ERROR_INVALID_SIG: i32 = 64; // Reserved for PKINIT
    pub const KDC_ERR_KEY_TOO_WEAK: i32 = 65; // Reserved for PKINIT
    pub const KDC_ERR_CERTIFICATE_MISMATCH: i32 = 66; // Reserved for PKINIT
    pub const KRB_AP_ERR_NO_TGT: i32 = 67; // No TGT available to validate USER-TO-USER
    pub const KDC_ERR_WRONG_REALM: i32 = 68; // Reserved for future use
    pub const KRB_AP_ERR_USER_TO_USER_REQUIRED: i32 = 69; // Ticket must be for USER-TO-USER
    pub const KDC_ERR_CANT_VERIFY_CERTIFICATE: i32 = 70; // Reserved for PKINIT
    pub const KDC_ERR_INVALID_CERTIFICATE: i32 = 71; // Reserved for PKINIT
    pub const KDC_ERR_REVOKED_CERTIFICATE: i32 = 72; // Reserved for PKINIT
    pub const KDC_ERR_REVOCATION_STATUS_UNKNOWN: i32 = 73; // Reserved for PKINIT
    pub const KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: i32 = 74; // Reserved for PKINIT
    pub const KDC_ERR_CLIENT_NAME_MISMATCH: i32 = 75; // Reserved for PKINIT
    pub const KDC_ERR_KDC_NAME_MISMATCH: i32 = 76; // Reserved for PKINIT
}
