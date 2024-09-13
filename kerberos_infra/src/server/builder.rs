use sqlx::PgPool;
use tokio::sync::RwLock;

use super::config::{Configuration, Protocol};
use super::host::AsyncReceiver;
use super::infra::cache::Cache;
use super::infra::database::postgres::{PgDbSettings, PostgresDb};
use super::infra::host::HostBuilder;
use super::infra::{KrbCache, KrbDatabase, KrbDbSchema, KrbHost};
use super::types::KrbAsyncReceiver;
use super::{Server, ServerResult};

pub fn load_from_dir<Db>() -> ServerResult<ServerBuilder<Db>> {
    let config = Configuration::load(None).map_err(|_| "Fail to load configuration")?;

    Ok(ServerBuilder::new(config))
}

pub fn load<Db>(dir: &str) -> ServerResult<ServerBuilder<Db>> {
    let config = Configuration::load(Some(dir)).map_err(|_| "Fail to load configuration")?;

    Ok(ServerBuilder::new(config))
}

pub trait Builder: Sized {
    type Db;

    fn build(self, protocol: Protocol) -> ServerResult<Server<Self::Db>>;
}

pub struct ServerBuilder<Db> {
    config: Configuration,
    host: HostBuilder<Db>,
}

pub struct NpgServerBuilder {
    state: ServerBuilder<PgPool>,
    settings: PgDbSettings,
    schema: KrbDbSchema,
}

impl NpgServerBuilder {
    fn cache(&self) -> KrbCache {
        KrbCache::new(RwLock::new(Cache::boxed(&self.state.config.cache)))
    }

    fn database(&self) -> KrbDatabase<<Self as Builder>::Db> {
        KrbDatabase::new(RwLock::new(PostgresDb::boxed(
            self.settings.clone(),
            self.schema.clone_box(),
        )))
    }

    fn host(self, protocol: Protocol) -> ServerResult<KrbHost<PgPool>> {
        let host = match protocol {
            Protocol::Udp => self.state.host.boxed_udp(),
            Protocol::Tcp => self.state.host.boxed_tcp(),
        }
        .map_err(|e| format!("Unable to start host. Error: {:?}", e))?;

        Ok(KrbHost::new(RwLock::new(host)))
    }
}

impl Builder for NpgServerBuilder {
    type Db = PgPool;

    fn build(self, protocol: Protocol) -> ServerResult<Server<Self::Db>> {
        let cache = self.cache();

        let database = self.database();

        let host = self.host(protocol)?;

        Ok(Server {
            host,
            cache,
            database,
        })
    }
}

impl<Db> ServerBuilder<Db> {
    pub fn new(config: Configuration) -> Self {
        let host = HostBuilder::new(&config.host);
        Self { config, host }
    }

    pub fn set_as_receiver(mut self, receiver: impl AsyncReceiver<Db = Db> + 'static) -> Self {
        self.host = self
            .host
            .set_as_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(receiver))));
        self
    }

    pub fn set_tgs_receiver(mut self, receiver: impl AsyncReceiver<Db = Db> + 'static) -> Self {
        self.host = self
            .host
            .set_tgs_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(receiver))));
        self
    }
}

impl ServerBuilder<PgPool> {
    pub fn use_postgres(self, settings: PgDbSettings, schema: KrbDbSchema) -> NpgServerBuilder {
        NpgServerBuilder {
            state: self,
            settings,
            schema,
        }
    }
}
