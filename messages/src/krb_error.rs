use der::Sequence;

use crate::basic::{
    Int32, KerberosString, KerberosTime, Microseconds, OctetString, PrincipalName, Realm,
};

#[derive(Sequence)]
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
        let pvno = Int32::new(b"\x05").expect("pvno");
        let msg_type = Int32::new(b"\x1e").expect("msg_type");
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
    pub const KDC_ERR_NONE: u8 = 0; // No error
    pub const KDC_ERR_NAME_EXP: u8 = 1; // Client's entry in database has expired
    pub const KDC_ERR_SERVICE_EXP: u8 = 2; // Server's entry in database has expired
    pub const KDC_ERR_BAD_PVNO: u8 = 3; // Requested protocol version number not supported
    pub const KDC_ERR_C_OLD_MAST_KVNO: u8 = 4; // Client's key encrypted in old master key
    pub const KDC_ERR_S_OLD_MAST_KVNO: u8 = 5; // Server's key encrypted in old master key
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: u8 = 6; // Client not found in Kerberos database
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: u8 = 7; // Server not found in Kerberos database
    pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: u8 = 8; // Multiple principal entries in database
    pub const KDC_ERR_NULL_KEY: u8 = 9; // The client or server has a null key
    pub const KDC_ERR_CANNOT_POSTDATE: u8 = 10; // Ticket not eligible for postdating
    pub const KDC_ERR_NEVER_VALID: u8 = 11; // Requested starttime is later than end time
    pub const KDC_ERR_POLICY: u8 = 12; // KDC policy rejects request
    pub const KDC_ERR_BADOPTION: u8 = 13; // KDC cannot accommodate requested option
    pub const KDC_ERR_ETYPE_NOSUPP: u8 = 14; // KDC has no support for encryption type
    pub const KDC_ERR_SUMTYPE_NOSUPP: u8 = 15; // KDC has no support for checksum type
    pub const KDC_ERR_PADATA_TYPE_NOSUPP: u8 = 16; // KDC has no support for padata type
    pub const KDC_ERR_TRTYPE_NOSUPP: u8 = 17; // KDC has no support for transited type
    pub const KDC_ERR_CLIENT_REVOKED: u8 = 18; // Client's credentials have been revoked
    pub const KDC_ERR_SERVICE_REVOKED: u8 = 19; // Credentials for server have been revoked
    pub const KDC_ERR_TGT_REVOKED: u8 = 20; // TGT has been revoked
    pub const KDC_ERR_CLIENT_NOTYET: u8 = 21; // Client not yet valid; try again later
    pub const KDC_ERR_SERVICE_NOTYET: u8 = 22; // Server not yet valid; try again later
    pub const KDC_ERR_KEY_EXPIRED: u8 = 23; // Password has expired; change password to reset
    pub const KDC_ERR_PREAUTH_FAILED: u8 = 24; // Pre-authentication information was invalid
    pub const KDC_ERR_PREAUTH_REQUIRED: u8 = 25; // Additional pre-authentication required
    pub const KDC_ERR_SERVER_NOMATCH: u8 = 26; // Requested server and ticket don't match
    pub const KDC_ERR_MUST_USE_USER2USER: u8 = 27; // Server principal valid for user2user only
    pub const KDC_ERR_PATH_NOT_ACCEPTED: u8 = 28; // KDC Policy rejects transited path
    pub const KDC_ERR_SVC_UNAVAILABLE: u8 = 29; // A service is not available
    pub const KRB_AP_ERR_BAD_INTEGRITY: u8 = 31; // Integrity check on decrypted field failed
    pub const KRB_AP_ERR_TKT_EXPIRED: u8 = 32; // Ticket expired
    pub const KRB_AP_ERR_TKT_NYV: u8 = 33; // Ticket not yet valid
    pub const KRB_AP_ERR_REPEAT: u8 = 34; // Request is a replay
    pub const KRB_AP_ERR_NOT_US: u8 = 35; // The ticket isn't for us
    pub const KRB_AP_ERR_BADMATCH: u8 = 36; // Ticket and authenticator don't match
    pub const KRB_AP_ERR_SKEW: u8 = 37; // Clock skew too great
    pub const KRB_AP_ERR_BADADDR: u8 = 38; // Incorrect net address
    pub const KRB_AP_ERR_BADVERSION: u8 = 39; // Protocol version mismatch
    pub const KRB_AP_ERR_MSG_TYPE: u8 = 40; // Invalid msg type
    pub const KRB_AP_ERR_MODIFIED: u8 = 41; // Message stream modified
    pub const KRB_AP_ERR_BADORDER: u8 = 42; // Message out of order
    pub const KRB_AP_ERR_BADKEYVER: u8 = 44; // Specified version of key is not available
    pub const KRB_AP_ERR_NOKEY: u8 = 45; // Service key not available
    pub const KRB_AP_ERR_MUT_FAIL: u8 = 46; // Mutual authentication failed
    pub const KRB_AP_ERR_BADDIRECTION: u8 = 47; // Incorrect message direction
    pub const KRB_AP_ERR_METHOD: u8 = 48; // Alternative authentication method required
    pub const KRB_AP_ERR_BADSEQ: u8 = 49; // Incorrect sequence number in message
    pub const KRB_AP_ERR_INAPP_CKSUM: u8 = 50; // Inappropriate type of checksum in message
    pub const KRB_AP_PATH_NOT_ACCEPTED: u8 = 51; // Policy rejects transited path
    pub const KRB_ERR_RESPONSE_TOO_BIG: u8 = 52; // Response too big for UDP; retry with TCP
    pub const KRB_ERR_GENERIC: u8 = 60; // Generic error (description in e-text)
    pub const KRB_ERR_FIELD_TOOLONG: u8 = 61; // Field is too long for this implementation
    pub const KDC_ERROR_CLIENT_NOT_TRUSTED: u8 = 62; // Reserved for PKINIT
    pub const KDC_ERROR_KDC_NOT_TRUSTED: u8 = 63; // Reserved for PKINIT
    pub const KDC_ERROR_INVALID_SIG: u8 = 64; // Reserved for PKINIT
    pub const KDC_ERR_KEY_TOO_WEAK: u8 = 65; // Reserved for PKINIT
    pub const KDC_ERR_CERTIFICATE_MISMATCH: u8 = 66; // Reserved for PKINIT
    pub const KRB_AP_ERR_NO_TGT: u8 = 67; // No TGT available to validate USER-TO-USER
    pub const KDC_ERR_WRONG_REALM: u8 = 68; // Reserved for future use
    pub const KRB_AP_ERR_USER_TO_USER_REQUIRED: u8 = 69; // Ticket must be for USER-TO-USER
    pub const KDC_ERR_CANT_VERIFY_CERTIFICATE: u8 = 70; // Reserved for PKINIT
    pub const KDC_ERR_INVALID_CERTIFICATE: u8 = 71; // Reserved for PKINIT
    pub const KDC_ERR_REVOKED_CERTIFICATE: u8 = 72; // Reserved for PKINIT
    pub const KDC_ERR_REVOCATION_STATUS_UNKNOWN: u8 = 73; // Reserved for PKINIT
    pub const KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: u8 = 74; // Reserved for PKINIT
    pub const KDC_ERR_CLIENT_NAME_MISMATCH: u8 = 75; // Reserved for PKINIT
    pub const KDC_ERR_KDC_NAME_MISMATCH: u8 = 76; // Reserved for PKINIT
}
