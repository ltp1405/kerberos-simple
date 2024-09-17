pub use types::{KrbAsyncReceiver, KrbCache, KrbDatabase, KrbDbSchema, KrbHost};

pub mod cache;

pub mod database;

pub mod host;

mod types {
    use sqlx::PgPool;
    use tokio::sync::RwLock;

    use super::cache::cacheable::Cacheable;
    use super::cache::CacheResultType;
    use super::database::{ClonableSchema, Database};
    use super::host::{AsyncReceiver, Runnable};

    pub type DataBox<T> = std::sync::Arc<RwLock<Box<T>>>;

    pub type KrbAsyncReceiver<T> = DataBox<dyn AsyncReceiver<Db = T>>;

    pub type KrbHost<T> = DataBox<dyn Runnable<Db = T>>;

    pub type KrbDatabase<T = PgPool> = DataBox<dyn Database<Inner = T>>;

    pub type KrbCache<K = Vec<u8>, V = CacheResultType> = DataBox<dyn Cacheable<K, V>>;

    pub type KrbDbSchema = Box<dyn ClonableSchema>;
}
