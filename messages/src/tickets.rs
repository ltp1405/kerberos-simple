use crate::basic::{
    EncryptedData, Int32, KerberosFlags, OctetString, PrincipalName, Realm,
    DEFAULT_PRINCIPAL_COMPONENTS_LEN,
};

// RFC 4120 Section 5.3
pub struct Ticket<const N: usize = DEFAULT_PRINCIPAL_COMPONENTS_LEN> {
    tkt_vno: Int32,
    realm: Realm,
    sname: PrincipalName<N>,
    enc_part: EncryptedData,
}

impl<const N: usize> Ticket<N> {
    pub fn new(
        tkt_vno: Int32,
        realm: Realm,
        sname: PrincipalName<N>,
        enc_part: EncryptedData,
    ) -> Self {
        Self {
            tkt_vno,
            realm,
            sname,
            enc_part,
        }
    }

    pub fn tkt_vno(&self) -> &Int32 {
        &self.tkt_vno
    }

    pub fn realm(&self) -> &str {
        self.realm.as_ref()
    }

    pub fn sname(&self) -> &PrincipalName<N> {
        &self.sname
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.enc_part
    }
}

pub type TicketFlags = KerberosFlags;

pub struct TransitedEncoding {
    tr_type: Int32, // must be registered
    contents: OctetString,
}

impl TransitedEncoding {
    pub fn new(tr_type: Int32, contents: OctetString) -> Self {
        Self { tr_type, contents }
    }

    pub fn tr_type(&self) -> &Int32 {
        &self.tr_type
    }

    pub fn contents(&self) -> &OctetString {
        &self.contents
    }
}
