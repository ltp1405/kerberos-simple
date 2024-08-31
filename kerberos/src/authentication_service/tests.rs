use crate::authentication_service::traits::{KeyFinder, ReplayCache, ReplayCacheEntry};
use crate::authentication_service::{AuthenticationService, AuthenticationServiceBuilder};
use crate::cryptography::Cryptography;
use crate::cryptography_error::CryptographyError;
use chrono::{DateTime, Local};
use messages::basic_types::{
    EncryptedData, EncryptionKey, KerberosString, KerberosTime, NameTypes, OctetString,
    PrincipalName, Realm,
};
use messages::{
    APOptions, ApReq, Authenticator, AuthenticatorBuilder, EncTicketPart, Encode, Ticket,
    TicketFlags, TransitedEncoding,
};
use std::time::{Duration, SystemTime};

struct MockedReplayCached;

impl ReplayCache for MockedReplayCached {
    type ReplayCacheError = &'static str;

    fn store(&self, entry: ReplayCacheEntry) -> Result<(), ReplayCacheEntry> {
        todo!()
    }

    fn contain(&self, entry: ReplayCacheEntry) -> Result<bool, ReplayCacheEntry> {
        todo!()
    }
}

struct MockedKeyStorage;

impl KeyFinder for MockedKeyStorage {
    fn get_key_for_srealm(&self, srealm: &Realm) -> Option<Vec<u8>> {
        todo!()
    }
}

struct MockedCrypto;

impl Cryptography for MockedCrypto {
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        Ok(data.into())
    }

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        Ok(data.into())
    }

    fn generate_key(&self) -> Result<Vec<u8>, CryptographyError> {
        Ok(Vec::from([0u8; 16]))
    }
}

#[test]
fn test_handle_ap_req() {
    let cache = MockedReplayCached;
    let key_storage = MockedKeyStorage;
    let crypto = MockedCrypto;
    let key = crypto.generate_key().unwrap();
    let auth_service = AuthenticationServiceBuilder::default()
        .accept_empty_address_ticket(true)
        .ticket_allowable_clock_skew(Duration::from_secs(60 * 5))
        .replay_cache(&cache)
        .key_finder(&key_storage)
        .crypto(&crypto)
        .build()
        .unwrap();

    let transited_encoding = TransitedEncoding::new(
        1,
        OctetString::new("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.".to_string().as_bytes()).unwrap(),
    );
    let ticket_inner = EncTicketPart::builder()
        .authtime(
            KerberosTime::from_unix_duration(Duration::new(
                Local::now().timestamp() as u64, /* u32 */
                0,
            ))
            .unwrap(),
        )
        .endtime(
            KerberosTime::from_unix_duration(
                Duration::from_secs(Local::now().timestamp() as u64 /* u32 */)
                    + Duration::from_secs(60 * 10),
            )
            .unwrap(),
        )
        .transited(transited_encoding)
        .crealm(Realm::new("me".to_string().as_bytes()).unwrap())
        .cname(
            PrincipalName::new(
                NameTypes::NtPrincipal,
                vec![KerberosString::new("me1".to_string().as_bytes()).unwrap()],
            )
            .unwrap(),
        )
        .key(EncryptionKey::new(
            0,
            OctetString::new(key.clone()).unwrap(),
        ))
        .flags(TicketFlags::builder().build().unwrap())
        .build()
        .unwrap()
        .to_der()
        .unwrap();
    let encrypted_ticket = crypto.encrypt(&ticket_inner, &key).unwrap();
    let ticket = Ticket::new(
        Realm::new("me".to_string().as_bytes()).unwrap(),
        PrincipalName::new(
            NameTypes::NtPrincipal,
            vec![KerberosString::new("me1".to_string().as_bytes()).unwrap()],
        )
        .unwrap(),
        EncryptedData::new(0, 0, OctetString::new(encrypted_ticket).unwrap()),
    );

    let authenticator = AuthenticatorBuilder::default()
        .ctime(
            KerberosTime::from_unix_duration(Duration::new(
                Local::now().timestamp() as u64, /* u32 */
                0,
            ))
                .unwrap(),
        )
        .cusec(0)
        .crealm(Realm::new("me".to_string().as_bytes()).unwrap())
        .cname(
            PrincipalName::new(
                NameTypes::NtPrincipal,
                vec![KerberosString::new("me1".to_string().as_bytes()).unwrap()],
            )
                .unwrap(),
        )
        .build()
        .unwrap()
        .to_der()
        .unwrap();
    let encrypted_authenticator = crypto.encrypt(&ticket_inner, &key).unwrap();
    let authenticator = EncryptedData::new(0, 0, OctetString::new(authenticator).unwrap());

    let ap_req = ApReq::new(APOptions::new(false, false), ticket, authenticator);

    assert!(auth_service.handle_krb_ap_req(ap_req).is_ok());
}
