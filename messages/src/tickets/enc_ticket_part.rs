use der::{DecodeValue, EncodeValue, FixedTag, Sequence, TagNumber};
use derive_builder::{Builder, UninitializedFieldError};

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

#[derive(Builder, Sequence, PartialEq, Eq, Clone, Debug)]
#[builder(setter(into, strip_option), public, build_fn(skip), name = "EncTicketPartBuilder")]
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
    pub fn builder() -> EncTicketPartBuilder {
        EncTicketPartBuilder::default()
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

impl EncTicketPartBuilder {
    pub fn build(&self) -> Result<EncTicketPart, UninitializedFieldError> {
        Ok(EncTicketPart(EncTicketPartInner {
            flags: self
                .clone()
                .flags
                .ok_or(UninitializedFieldError::new("flags"))?,
            key: self
                .clone()
                .key
                .ok_or(UninitializedFieldError::new("key"))?,
            crealm: self
                .clone()
                .crealm
                .ok_or(UninitializedFieldError::new("crealm"))?,
            cname: self
                .clone()
                .cname
                .ok_or(UninitializedFieldError::new("cname"))?,
            transited: self
                .clone()
                .transited
                .ok_or(UninitializedFieldError::new("transited"))?,
            authtime: self
                .authtime
                .ok_or(UninitializedFieldError::new("authtime"))?,
            starttime: self.starttime.flatten(),
            endtime: self
                .endtime
                .ok_or(UninitializedFieldError::new("endtime"))?,
            renew_till: self.renew_till.flatten(),
            caddr: self.caddr.clone().flatten(),
            authorization_data: self.authorization_data.clone().flatten(),
        }))
    }
}
