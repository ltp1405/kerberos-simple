use kerberos::client::client_env::ClientEnv;
use kerberos::cryptography::Cryptography;
use kerberos::service_traits::PrincipalDatabase;
use messages::Decode;

pub mod common;

mod tests {
    use crate::common::mocked::{
        MockClientEnv, MockedApReplayCache, MockedClientAddressStorage, MockedCrypto, MockedHasher,
        MockedLastReqDb, MockedPrincipalDb, MockedReplayCache, MockedUserSessionStorage,
    };
    use kerberos::application_authentication_service::{
        ApplicationAuthenticationService, ApplicationAuthenticationServiceBuilder,
    };
    use kerberos::authentication_service::{AuthenticationService, AuthenticationServiceBuilder};
    use kerberos::client::ap_exchange::prepare_ap_request;
    use kerberos::client::as_exchange::{prepare_as_request, receive_as_response};
    use kerberos::client::tgs_exchange::{prepare_tgs_request, receive_tgs_response};
    use kerberos::service_traits::{
        ApReplayCache, LastReqDatabase, PrincipalDatabase, ReplayCache,
    };
    use kerberos::ticket_granting_service::{TicketGrantingService, TicketGrantingServiceBuilder};
    use messages::basic_types::{
        AddressTypes, EncryptionKey, HostAddress, KerberosString, NameTypes, OctetString,
        PrincipalName, Realm,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn get_auth_service<P>(db: &P, pre_auth: bool) -> AuthenticationService<P>
    where
        P: PrincipalDatabase + Send + Sync,
    {
        AuthenticationServiceBuilder::default()
            .principal_db(db)
            .realm(Realm::new("realm".as_bytes()).unwrap())
            .sname(
                PrincipalName::new(
                    NameTypes::NtPrincipal,
                    [KerberosString::new("server").unwrap()],
                )
                .unwrap(),
            )
            .require_pre_authenticate(pre_auth)
            .supported_crypto_systems(vec![Box::new(MockedCrypto)])
            .build()
            .unwrap()
    }

    fn get_tgs_service<'a, P, C, L>(
        db: &'a P,
        replay_cache: &'a C,
        mocked_last_req_db: &'a L,
    ) -> TicketGrantingService<'a, P, C>
    where
        P: PrincipalDatabase + Send + Sync,
        C: ReplayCache + Send + Sync,
        L: LastReqDatabase + Send + Sync,
    {
        TicketGrantingServiceBuilder::default()
            .principal_db(db)
            .realm(Realm::new("realm".as_bytes()).unwrap())
            .name(
                PrincipalName::new(
                    NameTypes::NtPrincipal,
                    [KerberosString::new("server").unwrap()],
                )
                .unwrap(),
            )
            .replay_cache(replay_cache)
            .supported_crypto(vec![Box::new(MockedCrypto)])
            .supported_checksum(vec![Box::new(MockedHasher)])
            .last_req_db(mocked_last_req_db)
            .build()
            .unwrap()
    }

    fn get_ap_service<'a, C>(
        replay_cache: &'a C,
        address_storage: &'a MockedClientAddressStorage,
        session_storage: &'a MockedUserSessionStorage,
    ) -> ApplicationAuthenticationService<'a, C, MockedUserSessionStorage>
    where
        C: ApReplayCache + Sync + Send,
    {
        ApplicationAuthenticationServiceBuilder::default()
            .realm(Realm::new("realm".as_bytes()).unwrap())
            .sname(
                PrincipalName::new(
                    NameTypes::NtPrincipal,
                    [KerberosString::new("server").unwrap()],
                )
                .unwrap(),
            )
            .replay_cache(replay_cache)
            .session_storage(session_storage)
            .service_key(EncryptionKey::new(1, OctetString::new(vec![1; 8]).unwrap()))
            .accept_empty_address_ticket(true)
            .ticket_allowable_clock_skew(Duration::from_secs(60 * 10))
            .crypto(vec![Box::new(MockedCrypto)])
            .address_storage(address_storage)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_as_exchange() {
        let mock_client_env = MockClientEnv::new();
        let as_req =
            prepare_as_request(&mock_client_env, None, None, None).expect("Failed to prepare AS request");
        let auth_service = get_auth_service(&MockedPrincipalDb, false);
        let as_rep = auth_service.handle_krb_as_req(&as_req).await;
        assert!(as_rep.is_ok());
        let as_rep = as_rep.unwrap();
        assert!(receive_as_response(&mock_client_env, &as_req, &as_rep).is_ok());
    }

    #[tokio::test]
    async fn test_tgs_exchange() {
        let mock_client_env = MockClientEnv::new();
        let mock_replay_cache = MockedReplayCache::new();
        let mock_last_req_db = MockedLastReqDb::new();
        let as_req =
            prepare_as_request(&mock_client_env, None, None, None).expect("Failed to prepare AS request");
        let tgs_service =
            get_tgs_service(&MockedPrincipalDb, &mock_replay_cache, &mock_last_req_db);
        let as_service = get_auth_service(&MockedPrincipalDb, false);

        let as_rep = as_service.handle_krb_as_req(&as_req).await;
        assert!(as_rep.is_ok());
        let as_rep = as_rep.unwrap();
        println!(
            "{:?}",
            receive_as_response(&mock_client_env, &as_req, &as_rep)
        );

        let tgs_req = prepare_tgs_request(&mock_client_env).expect("Failed to prepare TGS request");
        let tgs_rep = tgs_service.handle_tgs_req(&tgs_req).await;
        let tgs_rep = tgs_rep.unwrap();
        println!(
            "{:?}",
            receive_tgs_response(&tgs_req, &tgs_rep, &mock_client_env)
        );
        assert!(receive_tgs_response(&tgs_req, &tgs_rep, &mock_client_env).is_ok());
    }

    #[tokio::test]
    async fn test_ap_exchange() {
        let mock_client_env = MockClientEnv::new();
        let mock_replay_cache = MockedReplayCache::new();
        let mock_last_req_db = MockedLastReqDb::new();
        let as_req =
            prepare_as_request(&mock_client_env, None, None, None).expect("Failed to prepare AS request");
        let tgs_service =
            get_tgs_service(&MockedPrincipalDb, &mock_replay_cache, &mock_last_req_db);
        let as_service = get_auth_service(&MockedPrincipalDb, false);

        let as_rep = as_service.handle_krb_as_req(&as_req).await;
        assert!(as_rep.is_ok());
        let as_rep = as_rep.unwrap();
        let session_storage = MockedUserSessionStorage::new();
        println!(
            "{:?}",
            receive_as_response(&mock_client_env, &as_req, &as_rep)
        );

        let tgs_req = prepare_tgs_request(&mock_client_env).expect("Failed to prepare TGS request");
        println!("{:?}", tgs_req.req_body().till());
        let tgs_rep = tgs_service.handle_tgs_req(&tgs_req).await;
        let tgs_rep = tgs_rep.unwrap();
        println!(
            "{:?}",
            receive_tgs_response(&tgs_req, &tgs_rep, &mock_client_env)
        );
        assert!(receive_tgs_response(&tgs_req, &tgs_rep, &mock_client_env).is_ok());

        let ap_cache = MockedApReplayCache::new();
        let address_storage = MockedClientAddressStorage::new();

        let ap_req = prepare_ap_request(&mock_client_env, false, None)
            .expect("Failed to prepare AP request");
        address_storage.add_address(
            ap_req.clone(),
            HostAddress::new(
                AddressTypes::Ipv4,
                OctetString::new(Ipv4Addr::new(192, 168, 1, 1).octets().as_slice()).unwrap(),
            )
            .unwrap(),
        );
        let ap_service = get_ap_service(&ap_cache, &address_storage, &session_storage);
        let ap_rep = ap_service.handle_krb_ap_req(ap_req).await;
        ap_rep.unwrap();
    }
}
