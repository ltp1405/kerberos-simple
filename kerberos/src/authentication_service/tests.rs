use crate::authentication_service::{AuthenticationService, AuthenticationServiceBuilder};
use crate::service_traits::{PrincipalDatabase, PrincipalDatabaseRecord};
use crate::tests_common::mocked::{MockedCrypto, MockedPrincipalDb};
use lazy_static::lazy_static;
use messages::basic_types::{EncryptionKey, HostAddresses, KerberosFlags, KerberosFlagsBuilder, KerberosString, KerberosTime, NameTypes, OctetString, PrincipalName, Realm};
use messages::flags::KdcOptionsFlag;
use messages::{AsReq, KdcReq, KdcReqBodyBuilder, TicketFlags};
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

struct KdcConfig {
    starttime: Option<KerberosTime>,
    till: KerberosTime,
    cname: PrincipalName,
    sname: PrincipalName,
    realm: Realm,
    postdate: bool,
}

impl Default for KdcConfig {
    fn default() -> Self {
        KdcConfig {
            starttime: None,
            till: KerberosTime::now() + Duration::from_secs(60*60),
            cname: CLIENT_NAME.clone(),
            sname: SERVER_NAME.clone(),
            realm: REALM.clone(),
            postdate: false,
        }
    }
}

fn make_as_req(cfg: &KdcConfig) -> AsReq {
    let mut flags = KerberosFlags::builder();
    if  cfg.postdate {
        flags.set(KdcOptionsFlag::ALLOW_POSTDATE as usize);
    }
    let kdc_req_body = KdcReqBodyBuilder::default()
        .kdc_options(flags.build().unwrap())
        .cname(cfg.cname.clone())
        .realm(cfg.realm.clone())
        .sname(cfg.sname.clone())
        .till(cfg.till.clone())
        .etype(vec![1, 2, 3])
        .nonce(123u32)
        .build()
        .unwrap();

    AsReq::new(
        None,
        kdc_req_body
    )
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

fn get_as_service<P: PrincipalDatabase + Sync + Send>(db: &P) -> AuthenticationService<P> {
    let crypto = MockedCrypto;
    AuthenticationServiceBuilder::default()
        .supported_crypto_systems(vec![Box::new(crypto)])
        .principal_db(db)
        .realm(REALM.clone())
        .require_pre_authenticate(false)
        .sname(SERVER_NAME.clone(),)
        .build()
        .unwrap()
}

#[tokio::test]
async fn test() {
    let principal_db = make_principal_db();
    let as_req = make_as_req(
        &KdcConfig {
            ..KdcConfig::default()
        }
    );
    let auth_service = get_as_service(&principal_db);
    auth_service
        .handle_krb_as_req(
            &as_req,
        )
        .await.unwrap();

    let as_req = make_as_req(
        &KdcConfig {
            starttime: Some(KerberosTime::now() - Duration::from_secs(60*60)),
            ..KdcConfig::default()
        }
    );
    auth_service
        .handle_krb_as_req(
            &as_req,
        )
        .await.unwrap();

}

#[tokio::test]
async fn test_postdate() {
    let principal_db = make_principal_db();
    let as_req = make_as_req(
        &KdcConfig {
            starttime: Some(KerberosTime::now() + Duration::from_secs(60*60*60)),
            ..KdcConfig::default()
        }
    );
    let auth_service = get_as_service(&principal_db);
    auth_service
        .handle_krb_as_req(
            &as_req,
        )
        .await.expect_err("Should fail due to invalid postdate");

}