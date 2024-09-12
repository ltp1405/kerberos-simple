use async_trait::async_trait;
pub use settings::SqliteDbSettings;

use super::{Database, DatabaseResult, Migration, Queryable, Schema};

pub struct SqlitePool {
    #[allow(dead_code)]
    schema: Box<dyn Schema>,
}

impl SqlitePool {
    pub fn boxed(_: SqliteDbSettings, schema: Box<dyn Schema>) -> Box<dyn Database> {
        Box::new(SqlitePool { schema })
    }
}

unsafe impl Send for SqlitePool {}
unsafe impl Sync for SqlitePool {}

#[async_trait]
impl Database for SqlitePool {}

#[async_trait]
impl Migration for SqlitePool {
    async fn migrate_then_seed(&mut self) -> DatabaseResult {
        Ok(())
    }
}

#[async_trait]
impl Queryable for SqlitePool {}

mod settings;
