use crate::{
    basic::{
        EncryptedData, HostAddresses, Int32, KerberosTime, PrincipalName, Realm, SequenceOf,
        UInt32,
    },
    spec_as_tgs_exchange::kdc_options::KdcOptions,
    tickets::Ticket,
};
use der::Sequence;

#[derive(Sequence)]
pub struct KdcReqBody {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub kdc_options: KdcOptions,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub cname: Option<PrincipalName>,

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    pub realm: Realm,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub sname: Option<PrincipalName>,

    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", optional = "true")]
    pub from: Option<KerberosTime>,

    #[asn1(context_specific = "5", tag_mode = "EXPLICIT")]
    pub till: KerberosTime,

    #[asn1(context_specific = "6", tag_mode = "EXPLICIT", optional = "true")]
    pub rtime: Option<KerberosTime>,

    #[asn1(context_specific = "7", tag_mode = "EXPLICIT")]
    pub nonce: UInt32,

    #[asn1(context_specific = "8", tag_mode = "EXPLICIT")]
    pub etype: SequenceOf<Int32>,

    #[asn1(context_specific = "9", tag_mode = "EXPLICIT", optional = "true")]
    pub addresses: Option<HostAddresses>,

    #[asn1(context_specific = "10", tag_mode = "EXPLICIT", optional = "true")]
    pub enc_authorization_data: Option<EncryptedData>,

    #[asn1(context_specific = "11", tag_mode = "EXPLICIT", optional = "true")]
    pub additional_tickets: Option<SequenceOf<Ticket>>,
}

impl KdcReqBody {
    pub fn new(
        kdc_options: impl Into<KdcOptions>,
        cname: impl Into<Option<PrincipalName>>,
        realm: impl Into<Realm>,
        sname: impl Into<Option<PrincipalName>>,
        from: impl Into<Option<KerberosTime>>,
        till: impl Into<KerberosTime>,
        rtime: impl Into<Option<KerberosTime>>,
        nonce: impl Into<UInt32>,
        etype: impl Into<SequenceOf<Int32>>,
        addresses: impl Into<Option<HostAddresses>>,
        enc_authorization_data: impl Into<Option<EncryptedData>>,
        additional_tickets: impl Into<Option<SequenceOf<Ticket>>>,
    ) -> Self {
        Self {
            kdc_options: kdc_options.into(),
            cname: cname.into(),
            realm: realm.into(),
            sname: sname.into(),
            from: from.into(),
            till: till.into(),
            rtime: rtime.into(),
            nonce: nonce.into(),
            etype: etype.into(),
            addresses: addresses.into(),
            enc_authorization_data: enc_authorization_data.into(),
            additional_tickets: additional_tickets.into(),
        }
    }

    pub fn kdc_options(&self) -> &KdcOptions {
        &self.kdc_options
    }

    pub fn cname(&self) -> Option<&PrincipalName> {
        self.cname.as_ref()
    }

    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    pub fn sname(&self) -> Option<&PrincipalName> {
        self.sname.as_ref()
    }

    pub fn from(&self) -> Option<&KerberosTime> {
        self.from.as_ref()
    }

    pub fn till(&self) -> &KerberosTime {
        &self.till
    }

    pub fn rtime(&self) -> Option<&KerberosTime> {
        self.rtime.as_ref()
    }

    pub fn nonce(&self) -> &UInt32 {
        &self.nonce
    }

    pub fn etype(&self) -> &SequenceOf<Int32> {
        &self.etype
    }

    pub fn addresses(&self) -> Option<&HostAddresses> {
        self.addresses.as_ref()
    }

    pub fn enc_authorization_data(&self) -> Option<&EncryptedData> {
        self.enc_authorization_data.as_ref()
    }

    pub fn additional_tickets(&self) -> Option<&SequenceOf<Ticket>> {
        self.additional_tickets.as_ref()
    }
}
