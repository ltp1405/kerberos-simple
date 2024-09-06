use messages::basic_types::{
    KerberosFlags, KerberosFlagsBuilder, KerberosString, NameTypes, PrincipalName, Realm,
};
use messages::flags::KdcOptionsFlag;
use messages::{AsReq, KdcReqBody, KdcReqBodyBuilder};

#[test]
fn dummy_test() {
    let kdc_req_body = KdcReqBodyBuilder::default()
        .kdc_options(
            KerberosFlags::builder()
                .set(KdcOptionsFlag::POSTDATED as usize)
                .build()
                .unwrap(),
        )
        .cname(
            PrincipalName::new(
                NameTypes::NtPrincipal,
                vec!["me".to_string().try_into().unwrap()],
            )
            .unwrap(),
        )
        .realm(KerberosString::try_from("me".to_string()).unwrap())
        .etype(vec![1, 2, 3])
        .nonce(123u32)
        .build()
        .unwrap();
    let as_req = AsReq::new(None, kdc_req_body);
}
