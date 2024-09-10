use std::time::Duration;

use async_trait::async_trait;
use schemas::Schemas;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};

use crate::server::config::DatabaseSettings;

use super::{Database, DatabaseError, DatabaseResult, Migration, Queryable};

impl From<DatabaseSettings> for PgPool {
    fn from(settings: DatabaseSettings) -> Self {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(2))
            .connect_lazy_with(settings.with_db())
    }
}

#[async_trait]
impl Migration for PgPool {
    async fn migrate(&self) -> DatabaseResult {
        let schemas = Schemas.to_string();
        self.execute(schemas.as_str()).await?;
        Ok(())
    }
}

#[async_trait]
impl Queryable for PgPool {}

#[async_trait]
impl Database for PgPool {}

impl From<sqlx::Error> for DatabaseError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::Configuration(_) => DatabaseError::ConfigurationError,
            sqlx::Error::Database(_) => DatabaseError::OperationalError,
            sqlx::Error::Io(_) => DatabaseError::ConnectionError,
            sqlx::Error::Tls(_) => DatabaseError::ConnectionError,
            sqlx::Error::Protocol(_) => DatabaseError::OperationalError,
            sqlx::Error::RowNotFound => DatabaseError::NotFound,
            sqlx::Error::Encode(_) => DatabaseError::InvalidRequest,
            sqlx::Error::Decode(_) => DatabaseError::InvalidRequest,
            sqlx::Error::AnyDriverError(_) => DatabaseError::OperationalError,
            sqlx::Error::PoolTimedOut => DatabaseError::ConnectionError,
            sqlx::Error::PoolClosed => DatabaseError::ConnectionError,
            sqlx::Error::WorkerCrashed => DatabaseError::InternalError,
            sqlx::Error::Migrate(_) => DatabaseError::OperationalError,
            _ => DatabaseError::InternalError,
        }
    }
}

mod schemas;
