use async_trait::async_trait;
use kerberos_infra::server::{
    host::{AsyncReceiver, ExchangeError, HostError, HostResult},
    types::{KrbCache, KrbDatabase},
};
use messages::{AsReq, Decode, Encode, TgsReq};
use sqlx::PgPool;

use crate::{
    algo::{AesGcm, Sha1},
    authentication_service::AuthenticationServiceBuilder,
    kdc_srv::configs::{AuthenticationServiceConfig, TicketGrantingServiceConfig},
    ticket_granting_service::TicketGrantingServiceBuilder,
};

use super::types::{NpglKdcCacheView, NpglKdcDbView};

pub struct NpglAsReqHandler(AuthenticationServiceConfig);

impl NpglAsReqHandler {
    pub fn new(config: AuthenticationServiceConfig) -> Self {
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
        println!("Received AS_REQ");
        let database = database.read();
        println!("Received AS_REQ1");

        let database = database.await;
        let npgl_db_view = NpglKdcDbView::new(database.as_ref());

        println!("Received AS_REQ2");
        let authentication_server = AuthenticationServiceBuilder::default()
            .realm(self.0.realm.clone())
            .sname(self.0.sname.clone())
            .require_pre_authenticate(self.0.require_preauth)
            .supported_crypto_systems(vec![Box::new(AesGcm::new())])
            .principal_db(&npgl_db_view)
            .build()
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

pub struct NpglTgsReqHandler(TicketGrantingServiceConfig);

impl NpglTgsReqHandler {
    pub fn new(config: TicketGrantingServiceConfig) -> Self {
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
        println!("Received TGS_REQ");
        let database = database.read().await;
        println!("Received TGS_REQ1");

        let mut cache = cache.write().await;

        let npgl_db_view = NpglKdcDbView::new(database.as_ref());

        let npgl_cache_view = NpglKdcCacheView::new(cache.as_mut());

        let tgs_service = TicketGrantingServiceBuilder::default()
            .realm(self.0.realm.clone())
            .name(self.0.sname.clone())
            .supported_crypto(vec![Box::new(AesGcm::new())])
            .supported_checksum(vec![Box::new(Sha1::new())])
            .principal_db(&npgl_db_view)
            .replay_cache(&npgl_cache_view)
            .last_req_db(&npgl_cache_view)
            .build()
            .expect("Failed to build ticket granting service");

        let tgs_req = TgsReq::from_der(bytes).unwrap();

        let reply = tgs_service.handle_tgs_req(&tgs_req).await.unwrap();

        Ok(reply.to_der().unwrap())
    }

    fn error(&self, _: ExchangeError) -> HostResult<Vec<u8>> {
        Err(HostError::Ignorable)
    }
}
