use crate::basic::application_tags;
use crate::basic::{
    AuthorizationData, Checksum, EncryptionKey, Int32, KerberosTime, Microseconds, PrincipalName,
    Realm,
};
use der::Tag::Application;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagNumber, Writer,
};
use derive_builder::Builder;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Authenticator(AuthenticatorInner);

#[derive(Builder, Sequence, PartialEq, Eq, Clone, Debug)]
#[builder(setter(into), public, build_fn(skip), name = "AuthenticatorBuilder")]
struct AuthenticatorInner {
    #[asn1(context_specific = "0")]
    #[builder(setter(skip))]
    authenticator_vno: u8,

    #[asn1(context_specific = "1")]
    crealm: Realm,

    #[asn1(context_specific = "2")]
    cname: PrincipalName,

    #[asn1(context_specific = "3", optional = "true")]
    cksum: Option<Checksum>,

    #[asn1(context_specific = "4")]
    cusec: Microseconds,

    #[asn1(context_specific = "5")]
    ctime: KerberosTime,

    #[asn1(context_specific = "6", optional = "true")]
    subkey: Option<EncryptionKey>,

    #[asn1(context_specific = "7", optional = "true")]
    seq_number: Option<Int32>,

    #[asn1(context_specific = "8", optional = "true")]
    authorization_data: Option<AuthorizationData>,
}

impl AuthenticatorInner {
    pub fn authenticator_vno(&self) -> u8 {
        self.authenticator_vno
    }

    pub fn crealm(&self) -> &Realm {
        &self.crealm
    }

    pub fn cname(&self) -> &PrincipalName {
        &self.cname
    }

    pub fn cksum(&self) -> Option<&Checksum> {
        self.cksum.as_ref()
    }

    pub fn cusec(&self) -> Microseconds {
        self.cusec
    }

    pub fn ctime(&self) -> KerberosTime {
        self.ctime
    }

    pub fn subkey(&self) -> Option<&EncryptionKey> {
        self.subkey.as_ref()
    }

    pub fn seq_number(&self) -> Option<Int32> {
        self.seq_number
    }

    pub fn authorization_data(&self) -> Option<&AuthorizationData> {
        self.authorization_data.as_ref()
    }
}

impl AuthenticatorBuilder {
    pub fn build(&self) -> Result<Authenticator, AuthenticatorBuilderError> {
        Ok(Authenticator(AuthenticatorInner {
            authenticator_vno: 5,
            crealm: self
                .crealm
                .clone()
                .ok_or(AuthenticatorBuilderError::UninitializedField("crealm"))?,
            cname: self
                .cname
                .clone()
                .ok_or(AuthenticatorBuilderError::UninitializedField("cname"))?,
            cksum: self.cksum.clone().flatten(),
            cusec: self
                .cusec
                .ok_or(AuthenticatorBuilderError::UninitializedField("cusec"))?,
            ctime: self
                .ctime
                .ok_or(AuthenticatorBuilderError::UninitializedField("ctime"))?,
            subkey: self.subkey.clone().flatten(),
            seq_number: self.seq_number.clone().flatten(),
            authorization_data: self.authorization_data.clone().flatten(),
        }))
    }
}

impl<'a> DecodeValue<'a> for Authenticator {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let inner = AuthenticatorInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for Authenticator {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for Authenticator {
    const TAG: Tag = Application {
        number: TagNumber::new(application_tags::AUTHENTICATOR),
        constructed: true,
    };
}
