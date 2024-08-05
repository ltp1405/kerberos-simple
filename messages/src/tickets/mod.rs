use der::{Decode, Encode, EncodeValue, FixedTag, Sequence, TagNumber};

use crate::basic::{
    application_tags, AuthorizationData, EncryptedData, EncryptionKey, HostAddresses, Int32,
    KerberosFlags, KerberosString, KerberosTime, OctetString, PrincipalName, Realm,
};

// RFC 4120 Section 5.3
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Ticket {
    tkt_vno: Int32,
    realm: Realm,
    sname: PrincipalName,
    enc_part: EncryptedData,
}

impl EncodeValue for Ticket {
    fn value_len(&self) -> der::Result<der::Length> {
        self.tkt_vno.value_len()?
            + self.realm.value_len()?
            + self.sname.value_len()?
            + self.enc_part.value_len()?
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.tkt_vno.encode(encoder)?;
        self.realm.encode(encoder)?;
        self.sname.encode(encoder)?;
        self.enc_part.encode(encoder)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for Ticket {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let tkt_vno = Int32::decode(decoder)?;
        let realm = Realm::decode(decoder)?;
        let sname = PrincipalName::decode(decoder)?;
        let enc_part = EncryptedData::decode(decoder)?;
        Ok(Self {
            tkt_vno,
            realm,
            sname,
            enc_part,
        })
    }
}

impl FixedTag for Ticket {
    const TAG: der::Tag = der::Tag::Application {
        constructed: true,
        number: TagNumber::new(application_tags::TICKET),
    };
}

impl Ticket {
    pub fn new(realm: Realm, sname: PrincipalName, enc_part: EncryptedData) -> Self {
        let tkt_vno = {
            let bytes = 5.to_der().expect("Cannot encode Int32");
            Int32::new(&bytes).expect("Cannot initialize Int32 from &[u8]")
        };
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

    pub fn sname(&self) -> &PrincipalName {
        &self.sname
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.enc_part
    }
}

pub type TicketFlags = KerberosFlags;

#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
pub struct TransitedEncoding {
    #[asn1(context_specific = "0")]
    tr_type: Int32, // must be registered
    #[asn1(context_specific = "1")]
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

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct EncTicketPart {
    flags: TicketFlags,
    key: EncryptionKey,
    crealm: Realm,
    cname: PrincipalName,
    transited: TransitedEncoding,
    authtime: KerberosTime,
    starttime: Option<KerberosTime>,
    endtime: KerberosTime,
    renew_till: Option<KerberosTime>,
    caddr: Option<HostAddresses>,
    authorization_data: Option<AuthorizationData>,
}

impl FixedTag for EncTicketPart {
    const TAG: der::Tag = der::Tag::ContextSpecific {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_TICKET_PART),
    };
}

impl EncodeValue for EncTicketPart {
    fn value_len(&self) -> der::Result<der::Length> {
        self.flags.encoded_len()?
            + self.key.value_len()?
            + self.crealm.value_len()?
            + self.cname.value_len()?
            + self.transited.value_len()?
            + self.authtime.value_len()?
            + self.starttime.encoded_len()?
            + self.endtime.value_len()?
            + self.renew_till.encoded_len()?
            + self.caddr.encoded_len()?
            + self.authorization_data.encoded_len()?
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.flags.encode(encoder)?;
        self.key.encode(encoder)?;
        self.crealm.encode(encoder)?;
        self.cname.encode(encoder)?;
        self.transited.encode(encoder)?;
        self.authtime.encode(encoder)?;
        self.starttime.encode(encoder)?;
        self.endtime.encode(encoder)?;
        self.renew_till.encode(encoder)?;
        self.caddr.encode(encoder)?;
        self.authorization_data.encode(encoder)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for EncTicketPart {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let flags = TicketFlags::decode(decoder)?;
        let key = EncryptionKey::decode(decoder)?;
        let crealm = Realm::decode(decoder)?;
        let cname = PrincipalName::decode(decoder)?;
        let transited = TransitedEncoding::decode(decoder)?;
        let authtime = KerberosTime::decode(decoder)?;
        let starttime = Option::<KerberosTime>::decode(decoder)?;
        let endtime = KerberosTime::decode(decoder)?;
        let renew_till = Option::<KerberosTime>::decode(decoder)?;
        let caddr = Option::<HostAddresses>::decode(decoder)?;
        let authorization_data = Option::<AuthorizationData>::decode(decoder)?;
        Ok(Self {
            flags,
            key,
            crealm,
            cname,
            transited,
            authtime,
            starttime,
            endtime,
            renew_till,
            caddr,
            authorization_data,
        })
    }
}

impl EncTicketPart {
    pub fn builder(
        flags: TicketFlags,
        key: EncryptionKey,
        crealm: Realm,
        cname: PrincipalName,
        authtime: KerberosTime,
        endtime: KerberosTime,
        transited: TransitedEncoding,
    ) -> TicketBuilder {
        TicketBuilder::new(flags, key, crealm, cname, authtime, endtime, transited)
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

    pub fn cname(&self) -> &PrincipalName {
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

    pub fn caddr(&self) -> Option<&HostAddresses> {
        self.caddr.as_ref()
    }

    pub fn authorization_data(&self) -> Option<&AuthorizationData> {
        self.authorization_data.as_ref()
    }
}

pub struct TicketBuilder {
    flags: TicketFlags,
    key: EncryptionKey,
    crealm: Realm,
    cname: PrincipalName,
    transited: TransitedEncoding,
    authtime: KerberosTime,
    starttime: Option<KerberosTime>,
    endtime: KerberosTime,
    renew_till: Option<KerberosTime>,
    caddr: Option<HostAddresses>,
    authorization_data: Option<AuthorizationData>,
}

impl TicketBuilder {
    fn new(
        flags: TicketFlags,
        key: EncryptionKey,
        crealm: Realm,
        cname: PrincipalName,
        authtime: KerberosTime,
        endtime: KerberosTime,
        transited: TransitedEncoding,
    ) -> Self {
        Self {
            flags,
            key,
            crealm,
            cname,
            transited,
            authtime,
            starttime: None,
            endtime,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        }
    }

    pub fn build(self) -> EncTicketPart {
        EncTicketPart {
            flags: self.flags,
            key: self.key,
            crealm: self.crealm,
            cname: self.cname,
            transited: self.transited,
            authtime: self.authtime,
            starttime: self.starttime,
            endtime: self.endtime,
            renew_till: self.renew_till,
            caddr: self.caddr,
            authorization_data: self.authorization_data,
        }
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

    pub fn cname(mut self, cname: PrincipalName) -> Self {
        self.cname = cname;
        self
    }

    pub fn transited(mut self, transited: TransitedEncoding) -> Self {
        self.transited = transited;
        self
    }

    pub fn authtime(mut self, authtime: KerberosTime) -> Self {
        self.authtime = authtime;
        self
    }

    pub fn starttime(mut self, starttime: KerberosTime) -> Self {
        self.starttime = Some(starttime);
        self
    }

    pub fn endtime(mut self, endtime: KerberosTime) -> Self {
        self.endtime = endtime;
        self
    }

    pub fn renew_till(mut self, renew_till: KerberosTime) -> Self {
        self.renew_till = Some(renew_till);
        self
    }

    pub fn caddr(mut self, caddr: HostAddresses) -> Self {
        self.caddr = Some(caddr);
        self
    }

    pub fn authorization_data(mut self, authorization_data: AuthorizationData) -> Self {
        self.authorization_data = Some(authorization_data);
        self
    }
}

#[cfg(test)]
mod test;