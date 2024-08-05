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
        kdc_options: KdcOptions,
        cname: Option<PrincipalName>,
        realm: Realm,
        sname: Option<PrincipalName>,
        from: Option<KerberosTime>,
        till: KerberosTime,
        rtime: Option<KerberosTime>,
        nonce: UInt32,
        etype: SequenceOf<Int32>,
        addresses: Option<HostAddresses>,
        enc_authorization_data: Option<EncryptedData>,
        additional_tickets: Option<SequenceOf<Ticket>>,
    ) -> Self {
        Self {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etype,
            addresses,
            enc_authorization_data,
            additional_tickets,
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
