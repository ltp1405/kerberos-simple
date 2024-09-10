use tokio::sync::RwLock;

use super::config::Configuration;
use super::infra::{host::HostBuilder, KrbCache, KrbDatabase, KrbHost};
use super::{AsyncReceiver, KrbAsyncReceiver, Server, ServerResult};

enum DatabaseOption {
    Postgres,
    Default,
}

pub struct ServerBuilder {
    config: Configuration,
    host: HostBuilder,
    database: DatabaseOption,
}

impl ServerBuilder {
    pub fn new(config: Configuration) -> Self {
        let host = HostBuilder::new(config.host.clone());
        Self {
            config,
            host,
            database: DatabaseOption::Default,
        }
    }

    pub fn set_as_receiver(mut self, receiver: impl AsyncReceiver + 'static) -> Self {
        self.host = self
            .host
            .as_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(receiver))));
        self
    }

    pub fn set_tgs_receiver(mut self, receiver: impl AsyncReceiver + 'static) -> Self {
        self.host = self
            .host
            .tgs_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(receiver))));
        self
    }

    pub fn with_postgres(mut self) -> Self {
        self.database = DatabaseOption::Postgres;
        self
    }

    #[cfg(feature = "server-tcp")]
    pub fn build_tcp(self) -> ServerResult<Server> {
        use sqlx::PgPool;

        use super::infra::cache::Cache;

        let host = KrbHost::new(RwLock::new(Box::new(
            self.host
                .build_tcp()
                .map_err(|_| "Fail to build TCP host")?,
        )));

        let cache = KrbCache::new(RwLock::new(Box::new(Cache::from(self.config.cache))));

        let database = match self.database {
            DatabaseOption::Postgres => {
                KrbDatabase::new(RwLock::new(Box::new(PgPool::from(self.config.database))))
            }
            DatabaseOption::Default => {
                KrbDatabase::new(RwLock::new(Box::new(PgPool::from(self.config.database))))
            }
        };

        Ok(Server {
            host,
            cache,
            database,
        })
    }

    #[cfg(feature = "server-udp")]
    pub fn build_udp(self) -> ServerResult<Server> {
        use sqlx::PgPool;

        use crate::server::infra::cache::Cache;

        let host = KrbHost::new(RwLock::new(Box::new(
            self.host
                .build_udp()
                .map_err(|_| "Fail to build TCP host")?,
        )));

        let cache = KrbCache::new(RwLock::new(Box::new(Cache::from(self.config.cache))));

        let database = match self.database {
            DatabaseOption::Postgres => {
                KrbDatabase::new(RwLock::new(Box::new(PgPool::from(self.config.database))))
            }
            DatabaseOption::Default => {
                KrbDatabase::new(RwLock::new(Box::new(PgPool::from(self.config.database))))
            }
        };

        Ok(Server {
            host,
            cache,
            database,
        })
    }
}
