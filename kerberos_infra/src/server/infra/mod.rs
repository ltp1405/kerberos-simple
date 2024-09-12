pub use types::{DataBox, KrbAsyncReceiver, KrbCache, KrbDatabase, KrbHost};

pub mod cache;

pub mod database;

pub mod host;

mod types {
    use sqlx::PgPool;
    use tokio::sync::RwLock;

    use super::cache::cacheable::Cacheable;
    use super::database::Database;
    use super::host::{AsyncReceiver, Runnable};

    pub type DataBox<T> = std::sync::Arc<RwLock<Box<T>>>;

    pub type KrbAsyncReceiver = DataBox<dyn AsyncReceiver>;

    pub type KrbHost = DataBox<dyn Runnable>;

    pub type KrbDatabase<T = PgPool> = DataBox<dyn Database<Inner = T>>;

    pub type KrbCache<K = String, V = String> = DataBox<dyn Cacheable<K, V>>;
}
