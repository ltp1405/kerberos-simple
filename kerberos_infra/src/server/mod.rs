// Public APIs
pub use builder::{
    load as load_server, load_from_dir as load_server_from_dir, Builder, ServerBuilder,
};

pub mod database {
    pub use crate::server::infra::database::{
        ClonableSchema, Database, DatabaseError, DbSettings, Migration, Schema,
    };

    pub use crate::server::infra::database::KrbV5Queryable;

    pub mod postgres {
        pub mod schemas {
            pub use crate::server::infra::database::postgres::Krb5DbSchemaV1;
        }

        pub use crate::server::infra::database::postgres::PgDbSettings;

        pub use crate::server::infra::database::postgres::PostgresDb;
    }

    pub use secrecy::ExposeSecret;
}

pub mod cache {
    pub use crate::server::infra::cache::cacheable::Cacheable;

    pub use crate::server::infra::cache::error::CacheResult;

    pub use crate::server::infra::cache::CacheResultType;
}

pub mod types {
    pub use crate::server::infra::{KrbAsyncReceiver, KrbCache, KrbDatabase, KrbDbSchema, KrbHost};

    pub use crate::server::config::Protocol;
}

pub mod host {
    pub use crate::server::infra::host::{AsyncReceiver, ExchangeError, HostError, HostResult};
}

use sqlx::PgPool;
use types::{KrbCache, KrbDatabase, KrbHost};

pub type NpglServer = Server<PgPool>;

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
        let _ = db_lock.downgrade();

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
