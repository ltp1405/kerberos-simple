use async_trait::async_trait;
use config::Config;

use crate::server::utils::Environment;

pub trait DbSettings: From<Config> {
    fn load_from_dir() -> Self {
        let builder = prepare("database");

        let config = builder.build().expect("Fail to build configuration");

        config.into()
    }

    fn load(dir: &str) -> Self {
        let builder = prepare(dir);

        let config = builder.build().expect("Fail to build configuration");

        config.into()
    }
}

fn prepare(dir: &str) -> config::ConfigBuilder<config::builder::DefaultState> {
    let base_path = std::env::current_dir().expect("Fail to read the base directory");

    let config = base_path.join(dir);

    let env: Environment = std::env::var("ENVIRONMENT")
        .unwrap_or("local".into())
        .try_into()
        .expect("Fail to parse environment");

    Config::builder()
        .add_source(config::File::from(config.join("base")))
        .add_source(config::File::from(config.join(env.as_str())))
}

pub trait Database: Migration + Queryable + Send + Sync {
    fn boxed(self: Box<Self>) -> Box<dyn Database>;
}

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

pub mod sqlite;

pub mod domain;
