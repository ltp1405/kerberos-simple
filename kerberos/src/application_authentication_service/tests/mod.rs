use crate::application_authentication_service::{
    ApplicationAuthenticationService, ApplicationAuthenticationServiceBuilder,
};
use crate::cryptography::Cryptography;
use crate::service_traits::{ApReplayCache, ClientAddressStorage};
use crate::tests_common::mocked::{
    MockedApReplayCache, MockedClientAddressStorage, MockedCrypto, MockedUserSessionStorage,
};
use messages::basic_types::{
    EncryptedData, EncryptionKey, HostAddresses, KerberosString, KerberosTime, NameTypes,
    OctetString, PrincipalName, Realm,
};
use messages::flags::TicketFlag;
use messages::{
    APOptions, ApReq, AuthenticatorBuilder, EncTicketPart, Encode, Ticket, TicketFlags,
    TransitedEncoding,
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

static SESSION_KEY: LazyLock<EncryptionKey> = LazyLock::new(|| {
    EncryptionKey::new(
        1,
        OctetString::new(vec![0x3; 16]).unwrap(), // Mocked key
    )
});

static SERVER_NAME: LazyLock<PrincipalName> = LazyLock::new(|| {
    PrincipalName::new(
        NameTypes::NtPrincipal,
        vec![KerberosString::new("SERVER".to_string().as_bytes()).unwrap()],
    )
    .unwrap()
});

static SERVER_REALM: LazyLock<Realm> = LazyLock::new(|| Realm::try_from("EXAMPLE.COM").unwrap());

static CLIENT_NAME: LazyLock<PrincipalName> = LazyLock::new(|| {
    PrincipalName::new(
        NameTypes::NtPrincipal,
        vec![KerberosString::new("CLIENT".to_string().as_bytes()).unwrap()],
    )
    .unwrap()
});

static CLIENT_REALM: LazyLock<Realm> = LazyLock::new(|| Realm::try_from("EXAMPLE.COM").unwrap());

struct TicketConfig {
    authtime: KerberosTime,
    starttime: KerberosTime,
    endtime: KerberosTime,
    renew_till: KerberosTime,
    flags: TicketFlags,
    key: EncryptionKey,
    cname: PrincipalName,
    crealm: Realm,
    caddr: HostAddresses,
}

impl Default for TicketConfig {
    fn default() -> Self {
        TicketConfig {
            authtime: KerberosTime::now(),
            starttime: KerberosTime::now(),
            endtime: KerberosTime::now() + Duration::from_secs(3600 * 24),
            renew_till: KerberosTime::now() + Duration::from_secs(3600 * 24),
            flags: TicketFlags::builder().build().unwrap(),
            key: SESSION_KEY.clone(),
            cname: CLIENT_NAME.clone(),
            crealm: CLIENT_REALM.clone(),
            caddr: vec![],
        }
    }
}

fn create_ap_service<'a>(
    ap_replay_cache: &'a MockedApReplayCache,
    address_storage: &'a MockedClientAddressStorage,
    session_storage: &'a MockedUserSessionStorage,
) -> ApplicationAuthenticationService<'a, MockedApReplayCache, MockedUserSessionStorage> {
    ApplicationAuthenticationServiceBuilder::default()
        .realm(SERVER_REALM.clone())
        .sname(SERVER_NAME.clone())
        .accept_empty_address_ticket(true)
        .ticket_allowable_clock_skew(Duration::from_secs(60 * 5))
        .replay_cache(ap_replay_cache)
        .crypto(vec![Box::new(MockedCrypto)])
        .session_storage(session_storage)
        .service_key(SERVER_KEY.to_owned())
        .address_storage(address_storage)
        .build()
        .unwrap()
}

fn make_ticket(config: &TicketConfig) -> Ticket {
    let enc_ticket = EncTicketPart::builder()
        .transited(TransitedEncoding::new(1, OctetString::new(vec![]).unwrap()))
        .key(config.key.clone())
        .cname(config.cname.clone())
        .crealm(config.crealm.clone())
        .flags(config.flags.clone())
        .authtime(config.authtime)
        .starttime(config.starttime)
        .endtime(config.endtime)
        .renew_till(config.renew_till)
        .caddr(config.caddr.clone())
        .build()
        .unwrap();
    let enc_ticket = MockedCrypto
        .encrypt(
            &enc_ticket.to_der().unwrap(),
            SERVER_KEY.keyvalue().as_bytes(),
        )
        .unwrap();
    let enc_ticket = EncryptedData::new(1, None, OctetString::new(enc_ticket).unwrap());
    Ticket::new(SERVER_REALM.clone(), SERVER_NAME.clone(), enc_ticket)
}

#[tokio::test]
async fn test_handle_ap_req() {
    let cache = MockedApReplayCache::new();
    let address_storage = MockedClientAddressStorage::new();
    let session_storage = MockedUserSessionStorage::new();
    let crypto = MockedCrypto;
    let transited_encoding = TransitedEncoding::new(
        1,
        OctetString::new("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.".to_string().as_bytes()).unwrap(),
    );
    let ticket = make_ticket(&TicketConfig::default());
    let authenticator = AuthenticatorBuilder::default()
        .ctime(KerberosTime::now())
        .cusec(0)
        .crealm(CLIENT_REALM.clone())
        .cname(CLIENT_NAME.clone())
        .build()
        .unwrap()
        .to_der()
        .unwrap();
    let encrypted_authenticator = crypto
        .encrypt(&authenticator, SESSION_KEY.keyvalue().as_bytes())
        .unwrap();
    let authenticator = EncryptedData::new(
        *SESSION_KEY.keytype(),
        None,
        OctetString::new(encrypted_authenticator).unwrap(),
    );

    let ap_req = ApReq::new(APOptions::new(false, false), ticket, authenticator);

    let auth_service = create_ap_service(&cache, &address_storage, &session_storage);
    assert!(auth_service
        .handle_krb_ap_req(ap_req.clone())
        .await
        .inspect_err(|e| println!("{:?}", e))
        .is_ok());

    auth_service
        .handle_krb_ap_req(ap_req)
        .await
        .expect_err("Should return error, this is a replay");
}

#[tokio::test]
async fn test_client_clock_skew() {
    let cache = MockedApReplayCache::new();
    let address_storage = MockedClientAddressStorage::new();
    let session_storage = MockedUserSessionStorage::new();
    let crypto = MockedCrypto;
    let transited_encoding = TransitedEncoding::new(
        1,
        OctetString::new("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.".to_string().as_bytes()).unwrap(),
    );
    let auth_service = create_ap_service(&cache, &address_storage, &session_storage);

    let ticket = make_ticket(&TicketConfig::default());
    let make_authenticator = |ctime: KerberosTime| {
        let authenticator = AuthenticatorBuilder::default()
            .ctime(ctime)
            .cusec(0)
            .crealm(CLIENT_REALM.clone())
            .cname(CLIENT_NAME.clone())
            .build()
            .unwrap()
            .to_der()
            .unwrap();
        let encrypted_authenticator = crypto
            .encrypt(&authenticator, SESSION_KEY.keyvalue().as_bytes())
            .unwrap();
        EncryptedData::new(
            *SESSION_KEY.keytype(),
            None,
            OctetString::new(encrypted_authenticator).unwrap(),
        )
    };

    let authenticator = make_authenticator(KerberosTime::now() + Duration::from_secs(60 * 100));
    let ap_req = ApReq::new(APOptions::new(false, false), ticket.clone(), authenticator);

    auth_service
        .handle_krb_ap_req(ap_req.clone())
        .await
        .expect_err("Should return error, client clock is too ahead of server");

    let authenticator = make_authenticator(KerberosTime::now() - Duration::from_secs(60 * 100));
    let ap_req = ApReq::new(APOptions::new(false, false), ticket, authenticator);
    auth_service
        .handle_krb_ap_req(ap_req.clone())
        .await
        .expect_err("Should return error, client clock is too behind of server");
}

#[tokio::test]
async fn test_ticket_time() {
    let cache = MockedApReplayCache::new();
    let address_storage = MockedClientAddressStorage::new();
    let session_storage = MockedUserSessionStorage::new();
    let crypto = MockedCrypto;
    let transited_encoding = TransitedEncoding::new(
        1,
        OctetString::new("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.".to_string().as_bytes()).unwrap(),
    );
    let ticket = make_ticket(&TicketConfig {
        starttime: KerberosTime::now() + Duration::from_secs(60 * 100),
        ..TicketConfig::default()
    });
    let authenticator = AuthenticatorBuilder::default()
        .ctime(KerberosTime::now())
        .cusec(0)
        .crealm(CLIENT_REALM.clone())
        .cname(CLIENT_NAME.clone())
        .build()
        .unwrap()
        .to_der()
        .unwrap();
    let encrypted_authenticator = crypto
        .encrypt(&authenticator, SESSION_KEY.keyvalue().as_bytes())
        .unwrap();
    let authenticator = EncryptedData::new(
        *SESSION_KEY.keytype(),
        None,
        OctetString::new(encrypted_authenticator).unwrap(),
    );

    let ap_req = ApReq::new(APOptions::new(false, false), ticket, authenticator.clone());

    let auth_service = create_ap_service(&cache, &address_storage, &session_storage);

    auth_service
        .handle_krb_ap_req(ap_req)
        .await
        .expect_err("Should return error, the ticket is not valid yet");

    let ticket = make_ticket(&TicketConfig {
        flags: TicketFlags::builder()
            .set(TicketFlag::INVALID as usize)
            .build()
            .expect("Should not failed"),
        ..TicketConfig::default()
    });

    let ap_req = ApReq::new(APOptions::new(false, false), ticket, authenticator.clone());
    auth_service
        .handle_krb_ap_req(ap_req)
        .await
        .expect_err("Should return error, the ticket is invalid");

    let ticket = make_ticket(&TicketConfig {
        endtime: KerberosTime::now() - Duration::from_secs(60 * 100),
        ..TicketConfig::default()
    });
    let ap_req = ApReq::new(APOptions::new(false, false), ticket, authenticator);
    auth_service
        .handle_krb_ap_req(ap_req.clone())
        .await
        .expect_err("Should return error, the ticket is expired");
}
