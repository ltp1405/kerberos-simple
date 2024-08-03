use der::Sequence;

use crate::basic::{
    AuthorizationData, EncryptedData, EncryptionKey, HostAddresses, Int32, KerberosFlags,
    KerberosString, KerberosTime, OctetString, PrincipalName, Realm, DEFAULT_HOSTS,
    DEFAULT_PRINCIPAL_COMPONENTS_LEN,
};

// RFC 4120 Section 5.3
#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct Ticket<const N: usize = DEFAULT_PRINCIPAL_COMPONENTS_LEN> {
    tkt_vno: Int32,
    realm: Realm,
    sname: PrincipalName<N>,
    enc_part: EncryptedData,
}

impl<const N: usize> Ticket<N> {
    pub fn new(realm: Realm, sname: PrincipalName<N>, enc_part: EncryptedData) -> Self {
        let tkt_vno = Int32::new(b"\x05").expect("Cannot initialize Int32 from &[u8]");
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

    pub fn realm(&self) -> &KerberosString {
        &self.realm
    }

    pub fn sname(&self) -> &PrincipalName<N> {
        &self.sname
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.enc_part
    }
}

pub type TicketFlags = KerberosFlags;

#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
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

#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct EncTicketPart<
    const H: usize = DEFAULT_HOSTS,
    const N: usize = DEFAULT_PRINCIPAL_COMPONENTS_LEN,
> {
    flags: TicketFlags,
    key: EncryptionKey,
    crealm: Realm,
    cname: PrincipalName<N>,
    transited: TransitedEncoding,
    authtime: KerberosTime,
    starttime: Option<KerberosTime>,
    endtime: KerberosTime,
    renew_till: Option<KerberosTime>,
    caddr: Option<HostAddresses<H>>,
    authorization_data: Option<AuthorizationData<N>>,
}

impl<const H: usize, const N: usize> EncTicketPart<H, N> {
    pub fn builder(
        flags: TicketFlags,
        key: EncryptionKey,
        crealm: Realm,
        cname: PrincipalName<N>,
        transited: TransitedEncoding,
    ) -> TicketBuilder<H, N> {
        TicketBuilder::new(flags, key, crealm, cname, transited)
    }

    pub fn flags(&self) -> &TicketFlags {
        &self.flags
    }

    pub fn key(&self) -> &EncryptionKey {
        &self.key
    }

    pub fn crealm(&self) -> &str {
        self.crealm.as_ref()
    }

    pub fn cname(&self) -> &PrincipalName<N> {
        &self.cname
    }

    pub fn transited(&self) -> &TransitedEncoding {
        &self.transited
    }

    pub fn authtime(&self) -> KerberosTime {
        self.authtime
    }

    pub fn starttime(&self) -> Option<KerberosTime> {
        self.starttime
    }

    pub fn endtime(&self) -> KerberosTime {
        self.endtime
    }

    pub fn renew_till(&self) -> Option<KerberosTime> {
        self.renew_till
    }

    pub fn caddr(&self) -> Option<&HostAddresses<H>> {
        self.caddr.as_ref()
    }

    pub fn authorization_data(&self) -> Option<&AuthorizationData<N>> {
        self.authorization_data.as_ref()
    }
}

pub struct TicketBuilder<
    const H: usize = DEFAULT_HOSTS,
    const N: usize = DEFAULT_PRINCIPAL_COMPONENTS_LEN,
> {
    flags: TicketFlags,
    key: EncryptionKey,
    crealm: Realm,
    cname: PrincipalName<N>,
    transited: TransitedEncoding,
    authtime: Option<KerberosTime>,
    starttime: Option<KerberosTime>,
    endtime: Option<KerberosTime>,
    renew_till: Option<KerberosTime>,
    caddr: Option<HostAddresses<H>>,
    authorization_data: Option<AuthorizationData<N>>,
}

impl<const H: usize, const N: usize> TicketBuilder<H, N> {
    fn new(
        flags: TicketFlags,
        key: EncryptionKey,
        crealm: Realm,
        cname: PrincipalName<N>,
        transited: TransitedEncoding,
    ) -> Self {
        Self {
            flags,
            key,
            crealm,
            cname,
            transited,
            authtime: None,
            starttime: None,
            endtime: None,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        }
    }

    pub fn build(self) -> Result<EncTicketPart<H, N>, &'static str> {
        if self.authtime.is_none() {
            return Err("authtime is required");
        }
        if self.endtime.is_none() {
            return Err("endtime is required");
        }
        Ok(EncTicketPart {
            flags: self.flags,
            key: self.key,
            crealm: self.crealm,
            cname: self.cname,
            transited: self.transited,
            authtime: self.authtime.unwrap(),
            starttime: self.starttime,
            endtime: self.endtime.unwrap(),
            renew_till: self.renew_till,
            caddr: self.caddr,
            authorization_data: self.authorization_data,
        })
    }

    pub fn flags(mut self, flags: TicketFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn key(mut self, key: EncryptionKey) -> Self {
        self.key = key;
        self
    }

    pub fn crealm(mut self, crealm: Realm) -> Self {
        self.crealm = crealm;
        self
    }

    pub fn cname(mut self, cname: PrincipalName<N>) -> Self {
        self.cname = cname;
        self
    }

    pub fn transited(mut self, transited: TransitedEncoding) -> Self {
        self.transited = transited;
        self
    }

    pub fn authtime(mut self, authtime: KerberosTime) -> Self {
        self.authtime = Some(authtime);
        self
    }

    pub fn starttime(mut self, starttime: KerberosTime) -> Self {
        self.starttime = Some(starttime);
        self
    }

    pub fn endtime(mut self, endtime: KerberosTime) -> Self {
        self.endtime = Some(endtime);
        self
    }

    pub fn renew_till(mut self, renew_till: KerberosTime) -> Self {
        self.renew_till = Some(renew_till);
        self
    }

    pub fn caddr(mut self, caddr: HostAddresses<H>) -> Self {
        self.caddr = Some(caddr);
        self
    }

    pub fn authorization_data(mut self, authorization_data: AuthorizationData<N>) -> Self {
        self.authorization_data = Some(authorization_data);
        self
    }
}
