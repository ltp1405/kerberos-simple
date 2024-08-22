use messages::basic_types::{
    AddressTypes, AuthorizationData, Checksum, EncryptedData, EncryptionKey, HostAddress,
    HostAddresses, KerberosFlags, KerberosString, KerberosTime, NameTypes, OctetString, PaData,
    PrincipalName, Realm, SequenceOf,
};
use messages::{AsRep, AsReq, EncTicketPart, KdcRep, KrbCredInfo, Ticket, TransitedEncoding};
use std::time::SystemTime;

// #[test]
// fn test_api() {
//     let kerberos_time = KerberosTime::from_system_time(SystemTime::now()).unwrap();
//     let host_address1 = HostAddress::new(AddressTypes::Ipv4, OctetString::new(&[1, 2, 3]));
//     let host_addresses = HostAddresses::new();
//
//     let authorization_data = AuthorizationData::new();
//
//     let pa_data = PaData::new(1, OctetString::new(&[2, 3, 4]));
//
//     let kerberos_flags = KerberosFlags::builder().set(1).set(5).build();
//
//     // panic!("kvno is optional")
//     let encrypted_data = EncryptedData::new(0, 1, OctetString::new(&[1, 2, 3]));
//
//     let checksum = Checksum::new(1, OctetString::new(&[2, 3, 4]));
//
//     let encryption_key = EncryptionKey::new(0, OctetString::new(&[1, 2, 3]));
//     let enc_ticket_part = EncTicketPart::builder(
//         kerberos_flags.unwrap(),
//         encryption_key,
//         Realm::try_from("ewete").unwrap(),
//         PrincipalName::new(
//             NameTypes::NtPrincipal,
//             [KerberosString::try_from("hello").unwrap()],
//         )
//         .unwrap(),
//         KerberosTime::from_system_time(SystemTime::now()).unwrap(),
//         KerberosTime::from_system_time(SystemTime::now()).unwrap(),
//         TransitedEncoding::new(0, OctetString::new(&[1, 2, 3]).unwrap()),
//     )
//     .build();
//
//     let as_rep = AsRep::new(
//         Some([pa_data.clone()]),
//         Realm::try_from("hello").unwrap(),
//         PrincipalName::new(
//             NameTypes::NtEnterprise,
//             [KerberosString::try_from("hello").unwrap()],
//         ),
//         Ticket::new(
//             Realm::try_from("hello").unwrap(),
//             PrincipalName::new(
//                 NameTypes::NtEnterprise,
//                 [KerberosString::try_from("hello").unwrap()],
//             )
//             .unwrap(),
//             encrypted_data.clone(),
//         ),
//         encrypted_data.clone(),
//     );
//
//     let kdc_rep = KdcRep::new(
//         Some([pa_data]),
//         1,
//         Realm::try_from("hello").unwrap(),
//         PrincipalName::new(
//             NameTypes::NtEnterprise,
//             [KerberosString::try_from("hello").unwrap()],
//         ),
//         Ticket::new(
//             Realm::try_from("hello").unwrap(),
//             PrincipalName::new(
//                 NameTypes::NtEnterprise,
//                 [KerberosString::try_from("hello").unwrap()],
//             )
//             .unwrap(),
//             encrypted_data.clone(),
//         ),
//         encrypted_data,
//     );
// }

#[test]
fn krb_as_req() {
    let pa_data = PaData::new(1, OctetString::new(&[1, 2, 3]).unwrap());
    let encrypted_data = EncryptedData::new(0, 1, OctetString::new(&[1, 2, 3]).unwrap());
    let as_rep = AsRep::new(
        Some(&[pa_data.clone()]),
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

    as_rep.crealm();
    as_rep.msg_type();
    as_rep.cname();
    as_rep.padata();
    as_rep.ticket();
    as_rep.enc_part();
}

#[test]
fn krb_error() {}

#[test]
fn krb_as_rep() {
    let data = AuthorizationData::new();
}

#[test]
fn krb_ap_rep() {}

#[test]
fn krb_ap_req() {}

#[test]
fn krb_tgs_rep() {}
#[test]
fn krb_tgs_req() {}
