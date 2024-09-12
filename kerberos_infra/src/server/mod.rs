// Public APIs
pub use builder::ServerBuilder;

pub use infra::{
    cache::{cacheable::Cacheable, error::CacheResult},
    database::{
        postgres::{PgDbSettings, PostgresDb}, sqlite::SqliteDbSettings, Database, DatabaseError, DbSettings,
        Krb5DbSchemaV1, Migration, Queryable, Schema,
    },
    host::{AsyncReceiver, ExchangeError, HostError, HostResult},
    KrbAsyncReceiver, KrbCache, KrbDatabase, KrbHost,
};

pub struct Server {
    host: KrbHost,
    cache: KrbCache,
    database: KrbDatabase,
}

impl Server {
    pub fn load_from_dir() -> ServerResult<ServerBuilder> {
        let config = Configuration::load(None).map_err(|_| "Fail to load configuration")?;

        Ok(ServerBuilder::new(config))
    }

    pub fn load(dir: &str) -> ServerResult<ServerBuilder> {
        let config = Configuration::load(Some(dir)).map_err(|_| "Fail to load configuration")?;

        Ok(ServerBuilder::new(config))
    }

    pub async fn prepare_and_run(&mut self) -> ServerResult {
        let mut db_lock = self.database.write().await;

        db_lock
            .migrate_then_seed()
            .await
            .map_err(|_| "Fail to initialize database")?;

        let database = self.database.clone();

        let cache = self.cache.clone();

        let mut host_lock = self.host.write().await;

        host_lock.run(database, cache).await;

        Ok(())
    }
}

// Private APIs
use config::Configuration;
type ServerResult<T = ()> = Result<T, String>;

// Modules
mod builder;
mod config;
mod infra;
mod utils;
