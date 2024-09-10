use async_trait::async_trait;

pub trait Database: Migration + Queryable + Send + Sync {}

pub type DatabaseResult<T = ()> = Result<T, DatabaseError>;

#[async_trait]
pub trait Migration {
    async fn migrate(&self) -> DatabaseResult;
}

#[async_trait]
pub trait Queryable {}

#[derive(Debug)]
pub enum DatabaseError {
    NotFound,           // Entity not found in the database
    InvalidRequest,     // Validation or encoding/decoding errors
    ConnectionError,    // Issues with connectivity, such as pool timeouts or IO errors
    ConfigurationError, // Configuration-related issues
    OperationalError,   // General database operation errors, such as migration or protocol errors
    InternalError,      // Catch-all for any other internal errors
}

pub mod postgres;

pub mod domain;
