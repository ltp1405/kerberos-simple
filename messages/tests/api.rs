use messages::basic_types::{
    AddressTypes, AuthorizationData, EncryptedData, EncryptionKey, HostAddress, HostAddresses,
    KerberosFlags, KerberosString, KerberosTime, NameTypes, OctetString, PaData, PrincipalName,
    Realm,
};
use messages::{
    APOptions, AsRep, Ecode, EncApRepPart, EncKdcRepPartBuilder, EncTicketPart, KrbApRep, KrbApReq,
    KrbErrorMsgBuilder, LastReqEntry, TgsRep, Ticket,
};
use std::time::{Duration, SystemTime};

#[test]
fn ticket() {
    let ticket = Ticket::new(
        Realm::try_from("hello").unwrap(),
        PrincipalName::new(
            NameTypes::NtEnterprise,
            [KerberosString::try_from("hello").unwrap()],
        )
        .unwrap(),
        EncryptedData::new(0, 1, OctetString::new(&[1, 2, 3]).unwrap()),
    );

    let enc_part = EncTicketPart::builder()
        .crealm(Realm::try_from("hello").unwrap())
        .cname(
            PrincipalName::new(
                NameTypes::NtEnterprise,
                [KerberosString::try_from("hello").unwrap()],
            )
            .unwrap(),
        )
        .caddr(HostAddresses::from(vec![HostAddress::new(
            AddressTypes::Ipv4,
            OctetString::new(&[1, 2, 3]).unwrap(),
        )
        .unwrap()]))
        .endtime(KerberosTime::from_unix_duration(Duration::from_secs(1)).unwrap());
}

#[test]
fn krb_as_req() {}

#[test]
fn krb_error() {
    let err = KrbErrorMsgBuilder::default()
        .error_code(Ecode::KDC_ERR_NAME_EXP)
        .sname(
            PrincipalName::new(
                NameTypes::NtEnterprise,
                [KerberosString::try_from("hello").unwrap()],
            )
            .unwrap(),
        )
        .e_data(OctetString::new(&[1, 2, 3]).ok())
        .e_text(KerberosString::try_from("hello").unwrap())
        .stime(KerberosTime::from_unix_duration(Duration::from_secs(1)).unwrap())
        .ctime(KerberosTime::from_unix_duration(Duration::from_secs(1)).unwrap())
        .realm(Realm::try_from("hello").unwrap())
        .crealm(Realm::try_from("hello").unwrap())
        .cusec(1)
        .susec(1)
        .build()
        .unwrap();

    err.ctime();
    err.susec();
    err.stime();
    err.susec();
    err.error_code();
    err.crealm();
    err.cname();
    err.realm();
    err.sname();
    err.e_text();
    err.e_data();
}

#[test]
fn krb_as_rep() {
    let data = AuthorizationData::new();
    let as_rep = AsRep::new(
        Some(vec![PaData::new(1, OctetString::new(&[1, 2, 3]).unwrap())]),
        Realm::try_from("hello").unwrap(),
        PrincipalName::new(
            NameTypes::NtEnterprise,
            [KerberosString::try_from("hello").unwrap()],
        )
        .unwrap(),
        Ticket::new(
            Realm::try_from("hello").unwrap(),
            PrincipalName::new(
                NameTypes::NtEnterprise,
                [KerberosString::try_from("hello").unwrap()],
            )
            .unwrap(),
            EncryptedData::new(0, 1, OctetString::new(&[1, 2, 3]).unwrap()),
        ),
        EncryptedData::new(0, 1, OctetString::new(&[1, 2, 3]).unwrap()),
    );
    as_rep.crealm();
    as_rep.cname();
    as_rep.padata();
    as_rep.ticket();
    as_rep.enc_part();
    as_rep.msg_type();
    as_rep.pvno();
}

#[test]
fn enc_kdc_rep_part() {
    let enc_part = EncKdcRepPartBuilder::default()
        .key(EncryptionKey::new(0, OctetString::new(&[1, 2, 3]).unwrap()))
        .last_req(vec![LastReqEntry::new(
            0,
            KerberosTime::from_unix_duration(Duration::from_secs(1)).unwrap(),
        )])
        .nonce(1_u32)
        .starttime(KerberosTime::from_unix_duration(Duration::from_secs(1)).unwrap())
        .endtime(KerberosTime::from_unix_duration(Duration::from_secs(1)).unwrap())
        .authtime(KerberosTime::from_system_time(SystemTime::now()).unwrap())
        .flags(KerberosFlags::builder().set(1).build().unwrap())
        .renew_till(KerberosTime::from_unix_duration(Duration::from_secs(1)).ok())
        .srealm(Realm::try_from("hello").unwrap())
        .sname(
            PrincipalName::new(
                NameTypes::NtEnterprise,
                [KerberosString::try_from("hello").unwrap()],
            )
            .unwrap(),
        )
        .key_expiration(KerberosTime::from_unix_duration(Duration::from_secs(1)).ok())
        .caddr(HostAddresses::from(vec![HostAddress::new(
            AddressTypes::Ipv4,
            OctetString::new(&[1, 2, 3]).unwrap(),
        )
        .unwrap()]))
        .build()
        .unwrap();

    enc_part.key();
    enc_part.last_req();
    enc_part.nonce();
    enc_part.key_expiration();
    enc_part.flags();
    enc_part.authtime();
    enc_part.starttime();
    enc_part.endtime();
    enc_part.renew_till();
    enc_part.srealm();
    enc_part.sname();
    enc_part.caddr();
}

#[test]
fn krb_ap_rep() {
    let ap_rep = KrbApRep::new(EncryptedData::new(0, 1, OctetString::new(&[2, 3]).unwrap()));

    let enc_data = EncApRepPart::new(
        KerberosTime::from_system_time(SystemTime::now()).unwrap(),
        1000,
        EncryptionKey::new(0, OctetString::new(&[1, 2, 3]).unwrap()),
        None,
    );

    ap_rep.msg_type();
    ap_rep.enc_part();
    ap_rep.pvno();

    enc_data.ctime();
    enc_data.cusec();
    enc_data.subkey();
    enc_data.seq_number();
}

#[test]
fn krb_ap_req() {
    let ticket = Ticket::new(
        Realm::new(&[1, 2, 3]).unwrap(),
        PrincipalName::new(
            NameTypes::NtPrincipal,
            vec![KerberosString::try_from("Hello".to_string()).unwrap()],
        )
        .unwrap(),
        EncryptedData::new(0, 1, OctetString::new(&[1, 2, 3]).unwrap()),
    );
    let ap_req = KrbApReq::new(
        APOptions::new(true, false),
        ticket,
        EncryptedData::new(0, 1, OctetString::new(&[1, 2, 3]).unwrap()),
    );

    ap_req.ticket();
    ap_req.pvno();
    ap_req.ap_options();
    ap_req.authenticator();
    ap_req.msg_type();
}

#[test]
fn krb_tgs_rep() {
    let pa_data = PaData::new(1, OctetString::new(&[1, 2, 3]).unwrap());
    let encrypted_data = EncryptedData::new(0, 1, OctetString::new(&[1, 2, 3]).unwrap());
    let tgs_rep = TgsRep::new(
        vec![pa_data.clone()],
        Realm::try_from("hello").unwrap(),
        PrincipalName::new(
            NameTypes::NtEnterprise,
            [KerberosString::try_from("hello").unwrap()],
        )
        .unwrap(),
        Ticket::new(
            Realm::try_from("hello".to_string()).unwrap(),
            PrincipalName::new(
                NameTypes::NtEnterprise,
                [KerberosString::try_from("hello").unwrap()],
            )
            .unwrap(),
            encrypted_data.clone(),
        ),
        encrypted_data.clone(),
    );

    tgs_rep.crealm();
    tgs_rep.cname();
    tgs_rep.padata();
    tgs_rep.ticket();
    tgs_rep.enc_part();
}
#[test]
fn tgs_req() {}
