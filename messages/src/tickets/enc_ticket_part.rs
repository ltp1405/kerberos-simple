use der::{DecodeValue, EncodeValue, FixedTag, Sequence, TagNumber};

use crate::basic::{
    application_tags, AuthorizationData, EncryptionKey, HostAddresses, KerberosTime, PrincipalName,
    Realm,
};

use super::{transited_encoding::TransitedEncoding, TicketFlags};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct EncTicketPart(EncTicketPartInner);

impl EncodeValue for EncTicketPart {
    fn value_len(&self) -> der::Result<der::Length> {
        self.0.value_len()
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode_value(encoder)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for EncTicketPart {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let inner = EncTicketPartInner::decode_value(reader, header)?;
        Ok(Self(inner))
    }
}

impl FixedTag for EncTicketPart {
    const TAG: der::Tag = der::Tag::ContextSpecific {
        constructed: true,
        number: TagNumber::new(application_tags::ENC_TICKET_PART),
    };
}

#[derive(Sequence, PartialEq, Eq, Clone, Debug)]
struct EncTicketPartInner {
    #[asn1(context_specific = "0")]
    flags: TicketFlags,
    #[asn1(context_specific = "1")]
    key: EncryptionKey,
    #[asn1(context_specific = "2")]
    crealm: Realm,
    #[asn1(context_specific = "3")]
    cname: PrincipalName,
    #[asn1(context_specific = "4")]
    transited: TransitedEncoding,
    #[asn1(context_specific = "5")]
    authtime: KerberosTime,
    #[asn1(context_specific = "6", optional = "true")]
    starttime: Option<KerberosTime>,
    #[asn1(context_specific = "7")]
    endtime: KerberosTime,
    #[asn1(context_specific = "8", optional = "true")]
    renew_till: Option<KerberosTime>,
    #[asn1(context_specific = "9", optional = "true")]
    caddr: Option<HostAddresses>,
    #[asn1(context_specific = "10", optional = "true")]
    authorization_data: Option<AuthorizationData>,
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
    ) -> EncTicketPartBuilder {
        EncTicketPartBuilder::new(flags, key, crealm, cname, authtime, endtime, transited)
    }

    pub fn flags(&self) -> &TicketFlags {
        &self.0.flags
    }

    pub fn key(&self) -> &EncryptionKey {
        &self.0.key
    }

    pub fn crealm(&self) -> &Realm {
        &self.0.crealm
    }

    pub fn cname(&self) -> &PrincipalName {
        &self.0.cname
    }

    pub fn transited(&self) -> &TransitedEncoding {
        &self.0.transited
    }

    pub fn authtime(&self) -> KerberosTime {
        self.0.authtime
    }

    pub fn starttime(&self) -> Option<KerberosTime> {
        self.0.starttime
    }

    pub fn endtime(&self) -> KerberosTime {
        self.0.endtime
    }

    pub fn renew_till(&self) -> Option<KerberosTime> {
        self.0.renew_till
    }

    pub fn caddr(&self) -> Option<&HostAddresses> {
        self.0.caddr.as_ref()
    }

    pub fn authorization_data(&self) -> Option<&AuthorizationData> {
        self.0.authorization_data.as_ref()
    }
}

pub struct EncTicketPartBuilder {
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

impl EncTicketPartBuilder {
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
        EncTicketPart(EncTicketPartInner {
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
