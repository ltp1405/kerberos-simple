use crate::authentication_service::AuthenticationServiceBuilder;
use crate::service_traits::PrincipalDatabaseRecord;
use crate::tests_common::mocked::{MockedCrypto, MockedPrincipalDb};
use lazy_static::lazy_static;
use messages::basic_types::{
    EncryptionKey, KerberosFlags,
    KerberosString, KerberosTime, NameTypes, OctetString, PrincipalName, Realm,
};
use messages::flags::KdcOptionsFlag;
use messages::{AsReq, KdcReqBodyBuilder};
use std::time::Duration;

lazy_static! {
    static ref CLIENT_NAME: PrincipalName = PrincipalName::new(
            NameTypes::NtPrincipal,
            vec![KerberosString::new("CLIENT".to_string().as_bytes()).unwrap()],
        ).unwrap();
    static ref REALM: Realm = Realm::try_from("EXAMPLE.COM").unwrap();
    static ref SERVER_NAME: PrincipalName = PrincipalName::new(
        NameTypes::NtPrincipal,
        vec![KerberosString::new("SERVER".to_string().as_bytes()).unwrap()],
    ).unwrap();
    static ref SERVER_KEY: EncryptionKey = EncryptionKey::new(
        1,
        OctetString::new([0x1; 16]).unwrap()
    );
}

fn make_principal_db() -> MockedPrincipalDb {
    let principal_database = MockedPrincipalDb::new();
    principal_database.add_principal(
        CLIENT_NAME.clone(),
        REALM.clone(),
        PrincipalDatabaseRecord {
            max_renewable_life: Duration::from_secs(3600 * 24),
            max_lifetime: Duration::from_secs(3600 * 24),
            key: EncryptionKey::new(
                1,
                OctetString::new(vec![0xa; 16]).unwrap(), // Mocked key
            ),
            p_kvno: None,
            supported_encryption_types: vec![1, 3, 23, 18],
        },
    );
    principal_database.add_principal(
        SERVER_NAME.clone(),
        REALM.clone(),
        PrincipalDatabaseRecord {
            max_renewable_life: Duration::from_secs(3600 * 24),
            max_lifetime: Duration::from_secs(3600 * 24),
            key: SERVER_KEY.clone(),
            p_kvno: None,
            supported_encryption_types: vec![1, 3, 23, 18],
        },
    );
    principal_database
}


#[tokio::test]
async fn dummy_test() {
    let kdc_req_body = KdcReqBodyBuilder::default()
        .kdc_options(
            KerberosFlags::builder()
                .set(KdcOptionsFlag::POSTDATED as usize)
                .build()
                .unwrap(),
        )
        .cname(CLIENT_NAME.clone())
        .realm(REALM.clone())
        .sname(SERVER_NAME.clone())
        .till(KerberosTime::now() + Duration::from_secs(5 * 60))
        .etype(vec![1, 2, 3])
        .nonce(123u32)
        .build()
        .unwrap();
    let crypto = MockedCrypto;
    let principal_db = make_principal_db();
    let as_req = AsReq::new(None, kdc_req_body);
    let auth_service = AuthenticationServiceBuilder::default()
        .supported_crypto_systems(vec![Box::new(crypto)])
        .principal_db(&principal_db)
        .realm(REALM.clone())
        .require_pre_authenticate(false)
        .sname(SERVER_NAME.clone(),)
        .build()
        .unwrap();
    auth_service
        .handle_krb_as_req(
            &as_req,
        )
        .await.unwrap();
}
