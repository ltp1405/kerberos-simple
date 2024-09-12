use std::mem;
use tokio::sync::RwLock;

use super::config::Configuration;
use super::infra::cache::Cache;
use super::infra::database::postgres::{PgDbSettings, PostgresDb};
use super::infra::database::sqlite::{SqliteDbSettings, SqlitePool};
use super::infra::database::Schema;
use super::infra::host::HostBuilder;
use super::infra::{KrbCache, KrbDatabase, KrbHost};
use super::{AsyncReceiver, KrbAsyncReceiver, Server, ServerResult};

enum DatabaseOption {
    Postgres(PgDbSettings),
    Sqlite(SqliteDbSettings),
    None,
}

pub struct ServerBuilder {
    config: Configuration,
    host: HostBuilder,
    database: DatabaseOption,
    schema: Option<Box<dyn Schema>>,
}

impl ServerBuilder {
    fn build_cache(&self) -> KrbCache {
        KrbCache::new(RwLock::new(Cache::boxed(&self.config.cache)))
    }

    fn build_database(&mut self) -> Option<KrbDatabase> {
        let schema = self.schema.take()?;

        let db_choice = mem::replace(&mut self.database, DatabaseOption::None);

        match db_choice {
            DatabaseOption::Postgres(settings) => Some(KrbDatabase::new(RwLock::new(
                PostgresDb::boxed(settings, schema),
            ))),
            DatabaseOption::Sqlite(settings) => Some(KrbDatabase::new(RwLock::new(
                SqlitePool::boxed(settings, schema),
            ))),
            DatabaseOption::None => None,
        }
    }
}

impl ServerBuilder {
    pub fn new(config: Configuration) -> Self {
        let host = HostBuilder::new(&config.host);
        Self {
            config,
            host,
            database: DatabaseOption::None,
            schema: None,
        }
    }

    pub fn set_as_receiver(mut self, receiver: impl AsyncReceiver + 'static) -> Self {
        self.host = self
            .host
            .set_as_receiver(KrbAsyncReceiver::new(RwLock::new(receiver.boxed())));
        self
    }

    pub fn set_tgs_receiver(mut self, receiver: impl AsyncReceiver + 'static) -> Self {
        self.host = self
            .host
            .set_tgs_receiver(KrbAsyncReceiver::new(RwLock::new(receiver.boxed())));
        self
    }

    pub fn with_schema(mut self, schema: Box<dyn Schema>) -> Self {
        self.schema = Some(schema);
        self
    }

    pub fn use_postgres(mut self, settings: PgDbSettings) -> Self {
        self.database = DatabaseOption::Postgres(settings);
        self
    }

    pub fn use_sqlite(mut self, settings: SqliteDbSettings) -> Self {
        self.database = DatabaseOption::Sqlite(settings);
        self
    }
}

#[cfg(feature = "server-tcp")]
impl ServerBuilder {
    pub fn build_tcp(mut self) -> ServerResult<Server> {
        let cache = self.build_cache();

        let database = self
            .build_database()
            .ok_or("Something went wrong when setting up database".to_owned())?;

        let host = KrbHost::new(RwLock::new(
            self.host
                .boxed_tcp()
                .map_err(|e| format!("Unable to start host. Error: {:?}", e))?,
        ));

        Ok(Server {
            host,
            cache,
            database,
        })
    }
}

#[cfg(feature = "server-udp")]
impl ServerBuilder {
    pub fn build_udp(mut self) -> ServerResult<Server> {
        let cache = self.build_cache();

        let database = self.build_database().ok_or("Database not set".to_owned())?;

        let host = KrbHost::new(RwLock::new(
            self.host
                .boxed_udp()
                .map_err(|e| format!("Unable to start host. Error: {:?}", e))?,
        ));

        Ok(Server {
            host,
            cache,
            database,
        })
    }
}
