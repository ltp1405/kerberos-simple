use crate::basic::{AddressTypes, Checksum, HostAddress, KerberosTime, OctetString};
use crate::krb_safe_spec::KrbSafe;
use der::{Decode, Encode};
use std::ops::Add;
use std::time::{Duration, UNIX_EPOCH};

fn minimal_krb_safe() -> KrbSafe {
    KrbSafe::builder()
        .set_user_data(OctetString::new(&[0x0, 0x1, 0x2]).unwrap())
        .set_cksum(Checksum::new(
            2,
            OctetString::new(&[0x0, 0x1, 0x2]).unwrap(),
        ))
        .set_s_address(
            HostAddress::new(
                AddressTypes::DecnetPhaseIv,
                OctetString::new(&[0x0, 0x1, 0x2]).unwrap(),
            )
            .unwrap(),
        )
        .build_unsafe()
}

#[test]
fn encode_then_decode() {
    let msg = minimal_krb_safe();
    let encoded_msg = msg.to_der().unwrap();
    println!("{:x?}", encoded_msg);

    let decoded_msg = KrbSafe::from_der(&encoded_msg).unwrap();

    assert_eq!(msg, decoded_msg);
}

#[test]
fn correct_encode_header() {
    let msg = minimal_krb_safe();

    let encoded_msg = msg.to_der().unwrap();
    #[rustfmt::skip]
    let expected_encoding = [
        0b0110_0000+20, 56, 48, 54, // APPLICATION 20
            160, 3, 2, 1, 5, // pnvo [0] INTEGER
            161, 3, 2, 1, 20, // msg-type [1] INTEGER
            162, 25, 48, 23, // safe-body [2] KRB-SAFE-BODY
                160, 5, 4, 3, 0, 1, 2, // user-data [0] OCTET STRING
                164, 14, 48, 12, //s-address [1] HostAddress
                    160, 3, 2, 1, 2,
                    161, 5, 4, 3, 0, 1, 2,
            163, 15, 48, 13, // check-sum [3] Checksum
                160, 4, 2, 2, 1, 2,
                161, 5, 4, 3, 0, 1, 2,
    ];
    assert_eq!(encoded_msg, expected_encoding);
}

#[test]
fn encode_optional_fields() {
    let msg = KrbSafe::builder()
        .set_user_data(OctetString::new(&[0x0, 0x1, 0x2]).unwrap())
        .set_timestamp(
            KerberosTime::from_system_time(UNIX_EPOCH.add(Duration::from_secs(1000000))).unwrap(),
        )
        .set_cksum(Checksum::new(
            2,
            OctetString::new(&[0x0, 0x1, 0x2]).unwrap(),
        ))
        .set_r_address(
            HostAddress::new(
                AddressTypes::Ipv4,
                OctetString::new(&[0x1, 0x2, 0x3]).unwrap(),
            )
            .unwrap(),
        )
        .set_s_address(
            HostAddress::new(
                AddressTypes::Ipv4,
                OctetString::new(&[0x0, 0x1, 0x2]).unwrap(),
            )
            .unwrap(),
        )
        .build_unsafe();

    let encoded = msg.to_der().unwrap();
    println!("{:?}", encoded);

    #[rustfmt::skip]
    let expected_encoding = vec![
        116, 90, 48, 88, // APPLICATION 20
            160, 3, 2, 1, 5, // pnvo [0] INTEGER
            161, 3, 2, 1, 20,// msg-type [1] INTEGER
            162, 60, 48, 58, // safe-body [2] KRB-SAFE-BODY
                160, 5, 4, 3, 0, 1, 2, // user-data [0] OCTET STRING
                161, 17, 24, 15, // timestamp [1] GeneralizedTime OPTIONAL
                    49, 57, 55, 48, 48, 49, 49, 50, 49, 51, 52, 54, 52, 48, 90,
                164, 14, 48, 12, // s-address [4] HostAddress
                    160, 3, 2, 1, 2,
                    161, 5, 4, 3, 0, 1, 2,
                165, 14, 48, 12, // r-address [5] HostAddress OPTIONAL
                    160, 3, 2, 1, 2,
                    161, 5, 4, 3, 1, 2, 3,
            163, 14, 48, 12, // cksum [3] Checksum
                160, 3, 2, 1, 2,
                161, 5, 4, 3, 0, 1, 2,
    ];

    assert_eq!(expected_encoding, msg.to_der().unwrap());
}
