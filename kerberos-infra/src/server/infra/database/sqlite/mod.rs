use async_trait::async_trait;
pub use settings::SqliteDbSettings;

use super::{Database, DatabaseResult, Migration, Queryable};

pub struct SqlitePool;

impl From<SqliteDbSettings> for Box<dyn Database> {
    fn from(_: SqliteDbSettings) -> Self {
        Box::new(SqlitePool).boxed()
    }
}

#[async_trait]
impl Database for SqlitePool {
    fn boxed(self: Box<Self>) -> Box<dyn Database> {
        self
    }
}

#[async_trait]
impl Migration for SqlitePool {
    async fn migrate(&self) -> DatabaseResult {
        Ok(())
    }
}

#[async_trait]
impl Queryable for SqlitePool {}

mod settings;
