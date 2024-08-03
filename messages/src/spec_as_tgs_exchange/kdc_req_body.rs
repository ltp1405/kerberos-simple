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
    pub kdc_options: KdcOptions,

    #[asn1(optional = "true")]
    pub cname: Option<PrincipalName>,

    pub realm: Realm,

    #[asn1(optional = "true")]
    pub sname: Option<PrincipalName>,

    #[asn1(optional = "true")]
    pub from: Option<KerberosTime>,

    pub till: KerberosTime,

    #[asn1(optional = "true")]
    pub rtime: Option<KerberosTime>,

    pub nonce: UInt32,

    pub etype: SequenceOf<Int32>,

    #[asn1(optional = "true")]
    pub addresses: Option<HostAddresses>,

    #[asn1(optional = "true")]
    pub enc_authorization_data: Option<EncryptedData>,

    #[asn1(optional = "true")]
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
}
