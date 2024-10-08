use std::time::Duration;

use der::{asn1::OctetString, Decode, Encode};

use crate::{
    basic::{
        flags, ADEntry, AddressTypes, EncryptedData, EncryptionKey, HostAddress, KerberosString,
        KerberosTime, NameTypes, PrincipalName, Realm,
    },
    tickets::{enc_ticket_part::EncTicketPart, transited_encoding::TransitedEncoding, Ticket},
};

use super::TicketFlags;

#[test]
fn ticket_should_have_tkt_vnu_equals_5() {
    let realm = Realm::new("EXAMPLE.COM").unwrap();
    let sname = {
        let name_type = NameTypes::NtEnterprise;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::new(name_type, name_string).unwrap()
    };
    let enc_part = EncryptedData::new(5, 5, OctetString::new("bytes".as_bytes()).unwrap());
    let ticket = Ticket::new(realm.clone(), sname.clone(), enc_part.clone());
    assert_eq!(ticket.tkt_vno(), &5);
    assert_eq!(ticket.realm(), &realm);
    assert_eq!(ticket.sname(), &sname);
    assert_eq!(ticket.enc_part(), &enc_part);
}

#[test]
fn encode_decode_for_ticket_works_fine() {
    let realm = Realm::new("EXAMPLE.COM").unwrap();
    let sname = {
        let name_type = NameTypes::NtEnterprise;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::new(name_type, name_string).unwrap()
    };
    let enc_part = EncryptedData::new(5, 5, OctetString::new("bytes".as_bytes()).unwrap());
    let ticket = Ticket::new(realm.clone(), sname.clone(), enc_part.clone());
    let bytes = ticket.to_der().unwrap();
    let decoded = Ticket::from_der(&bytes).unwrap();
    assert_eq!(decoded.tkt_vno(), &5);
    assert_eq!(decoded.realm(), &realm);
    assert_eq!(decoded.sname(), &sname);
    assert_eq!(decoded.enc_part(), &enc_part);
}

#[test]
fn transited_encoding_getter_works_fine() {
    let tr_type = 5;
    let contents = OctetString::new("bytes".as_bytes()).unwrap();
    let transited_encoding = TransitedEncoding::new(tr_type.clone(), contents.clone());
    assert_eq!(transited_encoding.tr_type(), &tr_type);
    assert_eq!(transited_encoding.contents(), &contents);
}

#[test]
fn encode_decode_for_transited_encoding_works_fine() {
    let tr_type = 5;
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
        .set(flags::KdcOptionsFlag::DISABLE_TRANSITED_CHECK as usize)
        .build()
        .unwrap();
    let key = EncryptionKey::new(5, OctetString::new("bytes".as_bytes()).unwrap());
    let crealm = Realm::new("EXAMPLE.COM").unwrap();
    let cname = {
        let name_type = NameTypes::NtEnterprise;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::new(name_type, name_string).unwrap()
    };
    let authtime = KerberosTime::from_unix_duration(Duration::from_secs(1619824155)).unwrap();
    let endtime = KerberosTime::from_unix_duration(Duration::from_secs(1619824160)).unwrap();
    let transited = TransitedEncoding::new(5, OctetString::new("bytes".as_bytes()).unwrap());
    let enc_ticket_part = EncTicketPart::builder()
        .flags(flags.clone())
        .key(key.clone())
        .crealm(crealm.clone())
        .cname(cname.clone())
        .authtime(authtime)
        .endtime(endtime)
        .transited(transited.clone())
        .build()
        .unwrap();

    assert_eq!(enc_ticket_part.flags(), &flags);
    assert_eq!(enc_ticket_part.key(), &key);
    assert_eq!(enc_ticket_part.crealm(), &crealm);
    assert_eq!(enc_ticket_part.cname(), &cname);
    assert_eq!(enc_ticket_part.authtime(), authtime);
    assert_eq!(enc_ticket_part.endtime(), endtime);
    assert_eq!(enc_ticket_part.transited(), &transited);
    assert!(enc_ticket_part.authorization_data().is_none());
    assert!(enc_ticket_part.caddr().is_none());
    assert!(enc_ticket_part.starttime().is_none());
    assert!(enc_ticket_part.renew_till().is_none());
}

#[test]
fn encode_decode_for_enc_ticket_part_works_fine() {
    let flags = TicketFlags::builder()
        .set(flags::KdcOptionsFlag::DISABLE_TRANSITED_CHECK as usize)
        .build()
        .unwrap();
    let key = EncryptionKey::new(5, OctetString::new("bytes".as_bytes()).unwrap());
    let crealm = Realm::new("EXAMPLE.COM").unwrap();
    let cname = {
        let name_type = NameTypes::NtEnterprise;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::new(name_type, name_string).unwrap()
    };
    let authtime = KerberosTime::from_unix_duration(Duration::from_secs(1619824155)).unwrap();
    let endtime = KerberosTime::from_unix_duration(Duration::from_secs(1619824160)).unwrap();
    let transited = TransitedEncoding::new(5, OctetString::new("bytes".as_bytes()).unwrap());
    let caddr = vec![HostAddress::new(
        AddressTypes::Iso,
        OctetString::new("bytes".as_bytes()).unwrap(),
    )
    .unwrap()];
    let authorization_data = vec![ADEntry::new(
        5,
        OctetString::new("bytes".as_bytes()).unwrap(),
    )];
    let enc_ticket_part = EncTicketPart::builder()
        .flags(flags.clone())
        .key(key.clone())
        .crealm(crealm.clone())
        .cname(cname.clone())
        .authtime(authtime)
        .endtime(endtime)
        .caddr(caddr.clone())
        .authorization_data(authorization_data.clone())
        .transited(transited.clone())
        .build()
        .unwrap();

    let bytes = enc_ticket_part.to_der().unwrap();
    let decoded = EncTicketPart::from_der(&bytes).unwrap();
    assert_eq!(decoded.flags(), &flags);
    assert_eq!(decoded.key(), &key);
    assert_eq!(decoded.crealm(), &crealm);
    assert_eq!(decoded.cname(), &cname);
    assert_eq!(decoded.authtime(), authtime);
    assert_eq!(decoded.endtime(), endtime);
    assert_eq!(decoded.transited(), &transited);
    assert_eq!(decoded.authorization_data(), Some(&authorization_data));
    assert_eq!(decoded.caddr(), Some(&caddr));
    assert!(decoded.starttime().is_none());
    assert!(decoded.renew_till().is_none());
}
