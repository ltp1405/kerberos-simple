use crate::authentication_service::{
    AuthenticationService, AuthenticationServiceBuilder, PrincipalDatabase,
};
use crate::cryptography::Cryptography;
use crate::cryptography_error::CryptographyError;
use messages::basic_types::{
    AddressTypes, EncryptionKey, HostAddress, Int32, KerberosFlags, KerberosFlagsBuilder,
    KerberosString, KerberosTime, NameTypes, OctetString, PrincipalName, Realm,
};
use messages::flags::KdcOptionsFlag;
use messages::{AsReq, KdcReqBody, KdcReqBodyBuilder};
use std::time::Duration;

struct MockedCrypto;

impl Cryptography for MockedCrypto {
    fn get_etype(&self) -> i32 {
        1
    }
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut data = data.to_vec();
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

impl PrincipalDatabase for MockedPrincipalDb {
    fn get_client_principal_key(
        &self,
        principal_name: &PrincipalName,
        realm: Realm,
    ) -> Vec<EncryptionKey> {
        vec![EncryptionKey::new(1, OctetString::new([1, 2, 3]).unwrap())]
    }

    fn get_server_principal_key(
        &self,
        principal_name: &PrincipalName,
        realm: Realm,
    ) -> Vec<EncryptionKey> {
        vec![EncryptionKey::new(1, OctetString::new([0xff; 8]).unwrap())]
    }

    fn get_server_supported_encryption_types(
        &self,
        principal_name: &PrincipalName,
        realm: Realm,
    ) -> Vec<Int32> {
        todo!()
    }
}

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
    auth_service
        .handle_krb_as_req(
            HostAddress::new(
                AddressTypes::Ipv4,
                OctetString::new("192.168.64.184".as_bytes()).unwrap(),
            )
            .unwrap(),
            &as_req,
        )
        .unwrap();
}
