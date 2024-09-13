use crate::authentication_service::AuthenticationServiceBuilder;
use crate::cryptography::Cryptography;
use crate::cryptography_error::CryptographyError;
use crate::service_traits::{PrincipalDatabase, PrincipalDatabaseRecord};
use async_trait::async_trait;
use messages::basic_types::{
    EncryptionKey, KerberosFlags, KerberosString, KerberosTime, NameTypes, OctetString,
    PrincipalName, Realm,
};
use messages::flags::KdcOptionsFlag;
use messages::{AsReq, KdcReqBodyBuilder};
use std::time::Duration;

struct MockedCrypto;

impl Cryptography for MockedCrypto {
    fn get_etype(&self) -> i32 {
        1
    }
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let data = data.to_vec();
        let data = data
            .iter()
            .zip(key.iter().cycle())
            .map(|(d, k)| *d ^ *k)
            .collect();
        Ok(data)
    }

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        self.encrypt(data, key)
    }

    fn generate_key(&self) -> Result<Vec<u8>, CryptographyError> {
        Ok(vec![0xff; 8])
    }
}

struct MockedPrincipalDb;

#[async_trait]
impl PrincipalDatabase for MockedPrincipalDb {
    async fn get_principal(
        &self,
        _principal_name: &PrincipalName,
        _realm: &Realm,
    ) -> Option<PrincipalDatabaseRecord> {
        Some(PrincipalDatabaseRecord {
            max_lifetime: Duration::from_secs(5 * 60),
            key: EncryptionKey::new(1, OctetString::new(vec![1; 8]).unwrap()),
            p_kvno: Some(1),
            max_renewable_life: Duration::from_secs(5 * 60),
            supported_encryption_types: vec![1, 2, 3],
        })
    }
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
        .cname(
            PrincipalName::new(
                NameTypes::NtPrincipal,
                vec!["me".to_string().try_into().unwrap()],
            )
            .unwrap(),
        )
        .realm(KerberosString::try_from("me".to_string()).unwrap())
        .sname(
            PrincipalName::new(
                NameTypes::NtPrincipal,
                ["me".to_string().try_into().unwrap()],
            )
            .unwrap(),
        )
        .till(KerberosTime::now() + Duration::from_secs(5 * 60))
        .etype(vec![1, 2, 3])
        .nonce(123u32)
        .build()
        .unwrap();
    let crypto = MockedCrypto;
    let principal_db = MockedPrincipalDb;
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
