use crate::cryptographic_hash::CryptographicHash;
use crate::cryptography::Cryptography;
use crate::service_traits::{PrincipalDatabase, PrincipalDatabaseRecord, ReplayCache};
use crate::tests_common::mocked::{MockedCrypto, MockedHasher, MockedLastReqDb, MockedPrincipalDb, MockedReplayCache};
use crate::ticket_granting_service::{TicketGrantingService, TicketGrantingServiceBuilder};
use messages::basic_types::{
    Checksum, EncryptedData, EncryptionKey, KerberosFlags, KerberosString, KerberosTime, NameTypes,
    OctetString, PaData, PrincipalName, SequenceOf,
};
use messages::{
    APOptions, ApReq, AuthenticatorBuilder, Decode, EncTicketPart,
    Encode, KdcReqBody, KdcReqBodyBuilder, TgsReq, Ticket, TransitedEncoding,
};
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

static  SESSION_KEY: LazyLock<EncryptionKey> = LazyLock::new(|| {
    EncryptionKey::new(
        1,
        OctetString::new(vec![0x3; 16]).unwrap(), // Mocked key
    )
});

fn make_principal_name_unsafe(name: &str) -> PrincipalName {
    PrincipalName::new(
        NameTypes::NtPrincipal,
        vec![KerberosString::new(name).unwrap()],
    )
    .unwrap()
}

fn make_principal_db() -> MockedPrincipalDb {
    let principal_database = MockedPrincipalDb::new();
    principal_database.add_principal(
        make_principal_name_unsafe("host"),
        KerberosString::new("EXAMPLE.COM").unwrap(),
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
        make_principal_name_unsafe("service"),
        KerberosString::new("EXAMPLE.COM").unwrap(),
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

fn make_basic_tgs_service<'a, P, C>(
    principal_database: &'a P,
    replay_cache: &'a C,
    mocked_last_req_db: &'a MockedLastReqDb,
) -> TicketGrantingService<'a, P, C>
where
    C: ReplayCache,
    P: PrincipalDatabase,
{
    TicketGrantingServiceBuilder::default()
        .name(make_principal_name_unsafe("tgs"))
        .realm(KerberosString::new("EXAMPLE.COM").unwrap())
        .principal_db(principal_database)
        .replay_cache(replay_cache)
        .supported_crypto(vec![Box::new(MockedCrypto)])
        .last_req_db(mocked_last_req_db)
        .supported_checksum(vec![Box::new(MockedHasher)])
        .build()
        .unwrap()
}

fn make_basic_tgs_request(
    sname: &str,
    realm: &str,
    cname: &str,
    pa_data: Option<fn(&KdcReqBody) -> SequenceOf<PaData>>,
) -> TgsReq {
    let till = KerberosTime::now() + Duration::from_secs(3600 * 24);
    let kdc_options = KerberosFlags::builder().build().unwrap();
    let kdc_body = KdcReqBodyBuilder::default()
        .sname(make_principal_name_unsafe(sname))
        .realm(KerberosString::new(realm).unwrap())
        .till(till)
        .cname(make_principal_name_unsafe(cname))
        .nonce(309346u32)
        .etype(vec![1, 3, 23, 18])
        .kdc_options(kdc_options)
        .build()
        .unwrap();
    TgsReq::new(pa_data.map(|f| f(&kdc_body)).unwrap_or_default(), kdc_body)
}

fn make_pa_data(kdc_req: &KdcReqBody) -> SequenceOf<PaData> {
    let enc_ticket = EncTicketPart::builder()
        .transited(TransitedEncoding::new(1, OctetString::new(vec![]).unwrap()))
        .key(SESSION_KEY.clone())
        .cname(make_principal_name_unsafe("user"))
        .crealm(KerberosString::new("EXAMPLE.COM").unwrap())
        .flags(KerberosFlags::builder().build().unwrap())
        .authtime(KerberosTime::now())
        .starttime(KerberosTime::now())
        .endtime(KerberosTime::now() + Duration::from_secs(3600 * 24))
        .renew_till(KerberosTime::now() + Duration::from_secs(3600 * 24))
        .caddr(vec![])
        .build()
        .unwrap();
    let enc_ticket = MockedCrypto
        .encrypt(
            &enc_ticket.to_der().unwrap(),
            SERVER_KEY.keyvalue().as_bytes(),
        )
        .unwrap();
    let enc_ticket = EncryptedData::new(1, None, OctetString::new(enc_ticket).unwrap());
    let ticket = Ticket::new(
        KerberosString::new("EXAMPLE.COM").unwrap(),
        make_principal_name_unsafe("host"),
        enc_ticket,
    );

    let checksum = MockedHasher.digest(&kdc_req.to_der().unwrap());
    let checksum = Checksum::new(1, OctetString::new(checksum).unwrap());

    let authenticator = AuthenticatorBuilder::default()
        .cname(make_principal_name_unsafe("user"))
        .crealm(KerberosString::new("EXAMPLE.COM").unwrap())
        .cusec(0)
        .ctime(KerberosTime::now())
        .cksum(checksum)
        .seq_number(0)
        .build()
        .unwrap();

    let enc_authenticator = MockedCrypto
        .encrypt(
            &authenticator.to_der().unwrap(),
            SESSION_KEY.keyvalue().as_bytes(),
        )
        .unwrap();

    let enc_authenticator =
        EncryptedData::new(1, None, OctetString::new(enc_authenticator).unwrap());

    let ap_req = ApReq::new(APOptions::new(false, false), ticket, enc_authenticator)
        .to_der()
        .unwrap();
    vec![PaData::new(1, OctetString::new(ap_req).unwrap())]
}

#[tokio::test]
async fn test_no_pa_data() {
    let tgs_req = make_basic_tgs_request("service", "EXAMPLE.COM", "user", None);
    let principal_db = make_principal_db();
    let replay_cache = MockedReplayCache::new();
    let mocked_last_req_db = MockedLastReqDb::new();

    let tgs_service = make_basic_tgs_service(&principal_db, &replay_cache, &mocked_last_req_db);
    tgs_service
        .handle_tgs_req(&tgs_req)
        .await
        .expect_err("Should fail because of no pre-authentication data");

    let tgs_req = make_basic_tgs_request(
        "service",
        "EXAMPLE.COM",
        "user",
        // Random pre-authentication data
        Some(|_| {
            vec![
                PaData::new(1, OctetString::new(vec![0x1, 0x2, 0x3, 0x4]).unwrap()),
                PaData::new(2, OctetString::new(vec![0x5, 0x6, 0x7, 0x8]).unwrap()),
            ]
        }),
    );

    let tgs_rep = tgs_service.handle_tgs_req(&tgs_req).await;
    tgs_rep.expect_err("Should fail because of unsupported pre-authentication data");
}

#[tokio::test]
async fn test_basic_request_processing() {
    let tgs_req = make_basic_tgs_request("service", "EXAMPLE.COM", "user", None);
    let principal_db = make_principal_db();
    let replay_cache = MockedReplayCache::new();
    let mocked_last_req_db = MockedLastReqDb::new();

    let tgs_service = make_basic_tgs_service(&principal_db, &replay_cache, &mocked_last_req_db);
    tgs_service
        .handle_tgs_req(&tgs_req)
        .await
        .expect_err("Should fail because of no pre-authentication data");

    let tgs_rep = tgs_service.handle_tgs_req(&tgs_req).await;
    tgs_rep.expect_err("Should fail because of unsupported pre-authentication data");

    let tgs_req = make_basic_tgs_request("service", "EXAMPLE.COM", "user", Some(make_pa_data));
    let tgs_rep = tgs_service
        .handle_tgs_req(&tgs_req)
        .await
        .expect("Should succeed");

    let enc_tgs_rep_part = MockedCrypto
        .decrypt(
            tgs_rep.ticket().enc_part().cipher().as_ref(),
            SERVER_KEY.keyvalue().as_bytes(),
        )
        .map(|data| EncTicketPart::from_der(&data).unwrap())
        .unwrap();
    assert_eq!(
        enc_tgs_rep_part.cname(),
        &make_principal_name_unsafe("user")
    );
}
