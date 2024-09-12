use crate::authentication_service::AuthenticationServiceBuilder;
use crate::tests_common::mocked::{MockedCrypto, MockedPrincipalDb};
use messages::basic_types::{
    EncryptionKey, KerberosFlags, KerberosString, KerberosTime, NameTypes, OctetString,
    PrincipalName, Realm,
};
use messages::flags::KdcOptionsFlag;
use messages::{AsReq, KdcReqBodyBuilder};
use std::sync::LazyLock;
use std::time::Duration;

static CLIENT_KEY: LazyLock<EncryptionKey> = LazyLock::new(|| {
    EncryptionKey::new(
        1,
        OctetString::new(vec![0x1; 16]).unwrap(), // Mocked key
    )
});

static SERVER_KEY: LazyLock<EncryptionKey> = LazyLock::new(|| {
    EncryptionKey::new(
        1,
        OctetString::new(vec![0x2; 16]).unwrap(), // Mocked key
    )
});

static SESSION_KEY: LazyLock<EncryptionKey> = LazyLock::new(|| {
    EncryptionKey::new(
        1,
        OctetString::new(vec![0x3; 16]).unwrap(), // Mocked key
    )
});

static SERVER_REALM: LazyLock<Realm> = LazyLock::new(|| Realm::try_from("EXAMPLE.COM").unwrap());

static SERVER_NAME: LazyLock<PrincipalName> = LazyLock::new(|| {
    PrincipalName::new(
        NameTypes::NtPrincipal,
        vec![KerberosString::new("SERVER".to_string().as_bytes()).unwrap()],
    )
    .unwrap()
});

static CLIENT_NAME: LazyLock<PrincipalName> = LazyLock::new(|| {
    PrincipalName::new(
        NameTypes::NtPrincipal,
        vec![KerberosString::new("CLIENT".to_string().as_bytes()).unwrap()],
    )
    .unwrap()
});

static CLIENT_REALM: LazyLock<Realm> = LazyLock::new(|| Realm::try_from("EXAMPLE.COM").unwrap());

#[tokio::test]
async fn test_01() {
    let kdc_req_body = KdcReqBodyBuilder::default()
        .kdc_options(
            KerberosFlags::builder()
                .set(KdcOptionsFlag::POSTDATED as usize)
                .build()
                .unwrap(),
        )
        .cname(CLIENT_NAME.to_owned())
        .realm(CLIENT_REALM.to_owned())
        .sname(SERVER_NAME.to_owned())
        .till(KerberosTime::now() + Duration::from_secs(5 * 60))
        .etype(vec![1, 2, 3])
        .nonce(123u32)
        .build()
        .unwrap();
    let crypto = MockedCrypto;
    let principal_db = MockedPrincipalDb::new();
    let as_req = AsReq::new(None, kdc_req_body);
    let auth_service = AuthenticationServiceBuilder::default()
        .supported_crypto_systems(vec![Box::new(crypto)])
        .principal_db(&principal_db)
        .realm("me".try_into().unwrap())
        .require_pre_authenticate(false)
        .sname(
            PrincipalName::new(
                NameTypes::NtPrincipal,
                vec!["me".to_string().try_into().unwrap()],
            )
            .unwrap(),
        )
        .build()
        .unwrap();
    auth_service.handle_krb_as_req(&as_req).await.unwrap();
}
