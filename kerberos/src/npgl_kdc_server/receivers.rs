use async_trait::async_trait;
use kerberos_infra::server::{
    host::{AsyncReceiver, ExchangeError, HostError, HostResult},
    types::{KrbCache, KrbDatabase},
};
use messages::{
    basic_types::{KerberosString, NameTypes, PrincipalName, Realm},
    AsReq, Decode, Encode, TgsReq,
};
use sqlx::PgPool;

use crate::{
    authentication_service::AuthenticationServiceBuilder,
    ticket_granting_service::TicketGrantingServiceBuilder,
};

use super::{
    types::{NpglKdcCacheView, NpglKdcDbView},
    NpglKdcSrcConfig,
};

pub struct NpglAsReqHandler(NpglKdcSrcConfig);

impl NpglAsReqHandler {
    pub fn new(config: NpglKdcSrcConfig) -> Self {
        Self(config)
    }
}

#[async_trait]
impl AsyncReceiver for NpglAsReqHandler {
    type Db = PgPool;

    async fn receive(
        &self,
        bytes: &[u8],
        database: KrbDatabase<Self::Db>,
        _: KrbCache,
    ) -> HostResult<Vec<u8>> {
        let database = database.read().await;

        let npgl_db_view = NpglKdcDbView::new(database.as_ref());

        let authentication_server = {
            let realm = Realm::new(&self.0.realm).expect("Invalid configuration value for realm");

            let svalue =
                vec![KerberosString::new(&self.0.sname)
                    .expect("Invalid configuration value for sname")];

            let sname = PrincipalName::new(NameTypes::NtPrincipal, svalue)
                .expect("Failed to create principal name");

            let supported_crypto_systems = vec![];

            AuthenticationServiceBuilder::default()
                .principal_db(&npgl_db_view)
                .realm(realm)
                .sname(sname)
                .require_pre_authenticate(self.0.require_preauth)
                .supported_crypto_systems(supported_crypto_systems)
                .build()
        }
        .expect("Failed to build authentication service");

        let as_req = AsReq::from_der(bytes).unwrap();

        let reply = authentication_server.handle_krb_as_req(&as_req).await?;

        Ok(reply.to_der().unwrap())
    }

    fn error(&self, _: ExchangeError) -> HostResult<Vec<u8>> {
        Err(HostError::Ignorable)
    }
}

impl From<crate::authentication_service::ServerError> for HostError {
    fn from(error: crate::authentication_service::ServerError) -> Self {
        match error {
            crate::authentication_service::ServerError::ProtocolError(reply) => Self::Actionable {
                reply: reply.to_der().unwrap(),
            },
            crate::authentication_service::ServerError::Internal => Self::Aborted { cause: None },
            crate::authentication_service::ServerError::CannotDecode => Self::Ignorable,
        }
    }
}

pub struct NpglTgsReqHandler(NpglKdcSrcConfig);

impl NpglTgsReqHandler {
    pub fn new(config: NpglKdcSrcConfig) -> Self {
        Self(config)
    }
}

#[async_trait]
impl AsyncReceiver for NpglTgsReqHandler {
    type Db = PgPool;

    async fn receive(
        &self,
        bytes: &[u8],
        database: KrbDatabase<Self::Db>,
        cache: KrbCache,
    ) -> HostResult<Vec<u8>> {
        let database = database.read().await;

        let mut cache = cache.write().await;

        let npgl_db_view = NpglKdcDbView::new(database.as_ref());

        let npgl_cache_view = NpglKdcCacheView::new(cache.as_mut());

        let tgs_service = {
            let realm = Realm::new(&self.0.realm).expect("Invalid configuration value for realm");

            let svalue =
                vec![KerberosString::new(&self.0.sname)
                    .expect("Invalid configuration value for sname")];

            let name = PrincipalName::new(NameTypes::NtPrincipal, svalue)
                .expect("Failed to create principal name");

            let supported_crypto_systems = vec![];

            let supported_checksum_systems = vec![];

            TicketGrantingServiceBuilder::default()
                .principal_db(&npgl_db_view)
                .replay_cache(&npgl_cache_view)
                .realm(realm)
                .name(name)
                .supported_crypto(supported_crypto_systems)
                .supported_checksum(supported_checksum_systems)
                .last_req_db(todo!("Implement last req db"))
                .build()
                .expect("Failed to build ticket granting service")
        };

        let tgs_req = TgsReq::from_der(bytes).unwrap();

        let reply = tgs_service.handle_tgs_req(&tgs_req).await.unwrap();

        Ok(reply.to_der().unwrap())
    }

    fn error(&self, _: ExchangeError) -> HostResult<Vec<u8>> {
        Err(HostError::Ignorable)
    }
}
