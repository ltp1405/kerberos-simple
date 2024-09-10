use crate::application_authentication_service::ApplicationAuthenticationServiceBuilder;
use crate::cryptography::Cryptography;
use crate::cryptography_error::CryptographyError;
use crate::service_traits::{
    ApReplayCache, ApReplayEntry, PrincipalDatabase, PrincipalDatabaseRecord, ReplayCache,
    ReplayCacheEntry,
};
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

impl ApReplayCache for MockedReplayCached {
    type ApReplayCacheError = ();

    fn store(&self, authenticator: &ApReplayEntry) -> Result<(), Self::ApReplayCacheError> {
        todo!()
    }

    fn contain(&self, authenticator: &ApReplayEntry) -> Result<bool, Self::ApReplayCacheError> {
        todo!()
    }
}

struct MockedKeyStorage;

impl PrincipalDatabase for MockedKeyStorage {
    fn get_principal(
        &self,
        principal_name: &PrincipalName,
        realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord> {
        todo!()
    }
}

struct MockedCrypto;

impl Cryptography for MockedCrypto {
    fn get_etype(&self) -> i32 {
        1
    }

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
        Realm::try_from("me".to_string()).unwrap(),
        PrincipalName::new(
            NameTypes::NtPrincipal,
            vec![KerberosString::try_from("me1".to_string()).unwrap()],
        )
        .unwrap(),
        EncryptedData::new(0, 0, OctetString::new(encrypted_ticket).unwrap()),
    );

    let authenticator = AuthenticatorBuilder::default()
        .ctime(KerberosTime::now())
        .cusec(0)
        .crealm(Realm::try_from("me".to_string()).unwrap())
        .cname(
            PrincipalName::new(
                NameTypes::NtPrincipal,
                vec!["me1".to_string().try_into().unwrap()],
            )
            .unwrap(),
        )
        .build()
        .unwrap()
        .to_der()
        .unwrap();
    let encrypted_authenticator = crypto.encrypt(&authenticator, &key).unwrap();
    let authenticator =
        EncryptedData::new(0, 0, OctetString::new(encrypted_authenticator).unwrap());

    let ap_req = ApReq::new(APOptions::new(false, false), ticket, authenticator);

    let auth_service = ApplicationAuthenticationServiceBuilder::default()
        .realm("me".try_into().unwrap())
        .sname(PrincipalName::new(NameTypes::NtPrincipal, vec!["me".try_into().unwrap()]).unwrap())
        .accept_empty_address_ticket(true)
        .ticket_allowable_clock_skew(Duration::from_secs(60 * 5))
        .replay_cache(&cache)
        .principal_db(&key_storage)
        .crypto(vec![Box::new(crypto)])
        .build()
        .unwrap();

    assert!(auth_service
        .handle_krb_ap_req(ap_req)
        .inspect_err(|e| println!("{:?}", e))
        .is_ok());
}
