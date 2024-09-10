// Public APIs
pub use builder::ServerBuilder;

pub use infra::{
    cache::{cacheable::Cacheable, error::CacheResult},
    database::{Database, DatabaseError, Migration, Queryable},
    host::{AsyncReceiver, ExchangeError, KrbInfraSvrResult},
    KrbAsyncReceiver, KrbCache, KrbDatabase, KrbHost,
};

pub struct Server {
    host: KrbHost,
    cache: KrbCache,
    database: KrbDatabase,
}

impl Server {
    pub fn load_from_dir() -> ServerResult<ServerBuilder> {
        let config = Configuration::load().map_err(|_| "Fail to load configuration")?;

        Ok(ServerBuilder::new(config))
    }

    pub async fn prepare_and_run(&mut self) -> ServerResult {
        let lock = self.database.write().await;

        lock.migrate()
            .await
            .map_err(|_| "Fail to initialize database")?;

        let mut host = self.host.write().await;

        host.run(self.database.clone(), self.cache.clone()).await;

        Ok(())
    }
}

// Private APIs
use config::Configuration;
type ServerResult<T = ()> = Result<T, &'static str>;

// Modules
mod builder;
mod config;
mod infra;
