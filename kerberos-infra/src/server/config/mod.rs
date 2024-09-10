use config::Config;
use environment::Environment;
use error::StartupError;

pub use cache::CacheSettings;
pub use database::DatabaseSettings;
pub use server::ServerSettings;
pub use protocol::Protocol;

pub struct Configuration {
    pub database: DatabaseSettings,
    pub cache: CacheSettings,
    pub host: ServerSettings,
}

impl Configuration {
    pub fn load() -> Result<Self, StartupError> {
        let builder = {
            let base_path = std::env::current_dir().expect("Fail to read the base directory");

            let config = base_path.join("configs");

            let env: Environment = std::env::var("ENVIRONMENT")
                .unwrap_or("local".into())
                .try_into()
                .expect("Fail to parse environment");

            Config::builder()
                .add_source(config::File::from(config.join("base")))
                .add_source(config::File::from(config.join(env.as_str())))
        };

        Ok(builder.build()?.try_into()?)
    }
}

impl TryFrom<Config> for Configuration {
    type Error = StartupError;

    fn try_from(config: Config) -> Result<Self, Self::Error> {
        let server: ServerSettings = config.get::<ServerSettings>("server")?;
        let database: DatabaseSettings = config.get::<DatabaseSettings>("database")?;
        let cache: CacheSettings = config.get::<CacheSettings>("cache")?;
        Ok(Configuration {
            host: server,
            database,
            cache,
        })
    }
}

mod cache;
mod database;
mod environment;
mod protocol;
mod error;
mod server;
