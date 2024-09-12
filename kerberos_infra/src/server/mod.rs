// Public APIs
pub use builder::{
    load as load_server, load_from_dir as load_server_from_dir, Builder, ServerBuilder,
};

pub use infra::{
    cache::{cacheable::Cacheable, error::CacheResult},
    database::{
        postgres::{PgDbSettings, PostgresDb},
        Database, DatabaseError, DbSettings, Krb5DbSchemaV1, Migration, Queryable, Schema,
    },
    host::{AsyncReceiver, ExchangeError, HostError, HostResult},
    KrbAsyncReceiver, KrbCache, KrbDatabase, KrbHost,
};

pub use config::Protocol;

pub struct Server<Db> {
    host: KrbHost<Db>,
    cache: KrbCache,
    database: KrbDatabase<Db>,
}

impl<T> Server<T> {
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
type ServerResult<T = ()> = Result<T, String>;

// Modules
mod builder;
mod config;
mod infra;
mod utils;
