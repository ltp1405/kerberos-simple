use std::time::Duration;

use der::{asn1::OctetString, Decode, Encode};

use crate::{
    basic::{
        flags, ntypes, ADEntry, EncryptedData, EncryptionKey, HostAddress, Int32, KerberosString,
        KerberosTime, PrincipalName, Realm,
    },
    tickets::{enc_ticket_part::EncTicketPart, transited_encoding::TransitedEncoding, Ticket},
};

use super::TicketFlags;

#[test]
fn ticket_should_have_tkt_vnu_equals_5() {
    let realm = Realm::new("EXAMPLE.COM").unwrap();
    let sname = {
        let name_type = ntypes::NT_ENTERPRISE;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::try_from(name_type, name_string).unwrap()
    };
    let enc_part = EncryptedData::new(
        Int32::new(&5.to_der().unwrap()).unwrap(),
        Int32::new(&5.to_der().unwrap()).unwrap(),
        OctetString::new("bytes".as_bytes()).unwrap(),
    );
    let ticket = Ticket::new(realm.clone(), sname.clone(), enc_part.clone());
    assert_eq!(
        ticket.as_ref().tkt_vno(),
        &Int32::new(&5.to_der().unwrap()).unwrap()
    );
    assert_eq!(ticket.as_ref().realm(), &realm);
    assert_eq!(ticket.as_ref().sname(), &sname);
    assert_eq!(ticket.as_ref().enc_part(), &enc_part);
}

#[test]
fn encode_decode_for_ticket_works_fine() {
    let realm = Realm::new("EXAMPLE.COM").unwrap();
    let sname = {
        let name_type = ntypes::NT_ENTERPRISE;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::try_from(name_type, name_string).unwrap()
    };
    let enc_part = EncryptedData::new(
        Int32::new(&5.to_der().unwrap()).unwrap(),
        Int32::new(&5.to_der().unwrap()).unwrap(),
        OctetString::new("bytes".as_bytes()).unwrap(),
    );
    let ticket = Ticket::new(realm.clone(), sname.clone(), enc_part.clone());
    let bytes = ticket.to_der().unwrap();
    let decoded = Ticket::from_der(&bytes).unwrap();
    assert_eq!(
        decoded.as_ref().tkt_vno(),
        &Int32::new(&5.to_der().unwrap()).unwrap()
    );
    assert_eq!(decoded.as_ref().realm(), &realm);
    assert_eq!(decoded.as_ref().sname(), &sname);
    assert_eq!(decoded.as_ref().enc_part(), &enc_part);
}

#[test]
fn transited_encoding_getter_works_fine() {
    let tr_type = Int32::new(&5.to_der().unwrap()).unwrap();
    let contents = OctetString::new("bytes".as_bytes()).unwrap();
    let transited_encoding = TransitedEncoding::new(tr_type.clone(), contents.clone());
    assert_eq!(transited_encoding.tr_type(), &tr_type);
    assert_eq!(transited_encoding.contents(), &contents);
}

#[test]
fn encode_decode_for_transited_encoding_works_fine() {
    let tr_type = Int32::new(&5.to_der().unwrap()).unwrap();
    let contents = OctetString::new("bytes".as_bytes()).unwrap();
    let transited_encoding = TransitedEncoding::new(tr_type.clone(), contents.clone());
    let bytes = transited_encoding.to_der().unwrap();
    let decoded = TransitedEncoding::from_der(&bytes).unwrap();
    assert_eq!(decoded.tr_type(), &tr_type);
    assert_eq!(decoded.contents(), &contents);
}

#[test]
fn enc_ticket_part_builder_works_fine() {
    let flags = TicketFlags::builder()
        .set(flags::DISABLE_TRANSITED_CHECK)
        .build()
        .unwrap();
    let key = EncryptionKey::new(
        Int32::new(&5.to_der().unwrap()).unwrap(),
        OctetString::new("bytes".as_bytes()).unwrap(),
    );
    let crealm = Realm::new("EXAMPLE.COM").unwrap();
    let cname = {
        let name_type = ntypes::NT_ENTERPRISE;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::try_from(name_type, name_string).unwrap()
    };
    let authtime = KerberosTime::from_unix_duration(Duration::from_secs(1619824155)).unwrap();
    let endtime = KerberosTime::from_unix_duration(Duration::from_secs(1619824160)).unwrap();
    let transited = TransitedEncoding::new(
        Int32::new(&5.to_der().unwrap()).unwrap(),
        OctetString::new("bytes".as_bytes()).unwrap(),
    );
    let enc_ticket_part = EncTicketPart::builder(
        flags.clone(),
        key.clone(),
        crealm.clone(),
        cname.clone(),
        authtime,
        endtime,
        transited.clone(),
    )
    .build();

    assert_eq!(enc_ticket_part.as_ref().flags(), &flags);
    assert_eq!(enc_ticket_part.as_ref().key(), &key);
    assert_eq!(enc_ticket_part.as_ref().crealm(), &crealm);
    assert_eq!(enc_ticket_part.as_ref().cname(), &cname);
    assert_eq!(enc_ticket_part.as_ref().authtime(), authtime);
    assert_eq!(enc_ticket_part.as_ref().endtime(), endtime);
    assert_eq!(enc_ticket_part.as_ref().transited(), &transited);
    assert!(enc_ticket_part.as_ref().authorization_data().is_none());
    assert!(enc_ticket_part.as_ref().caddr().is_none());
    assert!(enc_ticket_part.as_ref().starttime().is_none());
    assert!(enc_ticket_part.as_ref().renew_till().is_none());
}

#[test]
fn encode_decode_for_enc_ticket_part_works_fine() {
    let flags = TicketFlags::builder()
        .set(flags::DISABLE_TRANSITED_CHECK)
        .build()
        .unwrap();
    let key = EncryptionKey::new(
        Int32::new(&5.to_der().unwrap()).unwrap(),
        OctetString::new("bytes".as_bytes()).unwrap(),
    );
    let crealm = Realm::new("EXAMPLE.COM").unwrap();
    let cname = {
        let name_type = ntypes::NT_ENTERPRISE;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::try_from(name_type, name_string).unwrap()
    };
    let authtime = KerberosTime::from_unix_duration(Duration::from_secs(1619824155)).unwrap();
    let endtime = KerberosTime::from_unix_duration(Duration::from_secs(1619824160)).unwrap();
    let transited = TransitedEncoding::new(
        Int32::new(&5.to_der().unwrap()).unwrap(),
        OctetString::new("bytes".as_bytes()).unwrap(),
    );
    let caddr =
        vec![HostAddress::try_from(2, OctetString::new("bytes".as_bytes()).unwrap()).unwrap()];
    let authorization_data = vec![ADEntry::new(
        Int32::new(&5.to_der().unwrap()).unwrap(),
        OctetString::new("bytes".as_bytes()).unwrap(),
    )];
    let enc_ticket_part = EncTicketPart::builder(
        flags.clone(),
        key.clone(),
        crealm.clone(),
        cname.clone(),
        authtime,
        endtime,
        transited.clone(),
    )
    .caddr(caddr.clone())
    .authorization_data(authorization_data.clone())
    .build();

    let bytes = enc_ticket_part.to_der().unwrap();
    let decoded = EncTicketPart::from_der(&bytes).unwrap();
    assert_eq!(decoded.as_ref().flags(), &flags);
    assert_eq!(decoded.as_ref().key(), &key);
    assert_eq!(decoded.as_ref().crealm(), &crealm);
    assert_eq!(decoded.as_ref().cname(), &cname);
    assert_eq!(decoded.as_ref().authtime(), authtime);
    assert_eq!(decoded.as_ref().endtime(), endtime);
    assert_eq!(decoded.as_ref().transited(), &transited);
    assert_eq!(
        decoded.as_ref().authorization_data(),
        Some(&authorization_data)
    );
    assert_eq!(decoded.as_ref().caddr(), Some(&caddr));
    assert!(decoded.as_ref().starttime().is_none());
    assert!(decoded.as_ref().renew_till().is_none());
}
