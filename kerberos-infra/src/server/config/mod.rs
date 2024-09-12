use config::Config;
use error::StartupError;

pub use cache::CacheSettings;
pub use host::HostSettings;

use super::utils::Environment;

#[cfg(test)]
pub use protocol::Protocol;

pub struct Configuration {
    pub cache: CacheSettings,
    pub host: HostSettings,
}

impl Configuration {
    pub fn load(dir: Option<&str>) -> Result<Self, StartupError> {
        let builder = {
            let base_path = std::env::current_dir().expect("Fail to read the base directory");

            let config = base_path.join(dir.unwrap_or("server"));

            let env: Environment = std::env::var("ENVIRONMENT")
                .unwrap_or("local".into())
                .try_into()
                .expect("Fail to parse environment");

            Config::builder()
                .add_source(config::File::from(config.join("base")))
                .add_source(config::File::from(config.join(env.as_str())))
        };

        builder.build()?.try_into()
    }
}

impl TryFrom<Config> for Configuration {
    type Error = StartupError;

    fn try_from(config: Config) -> Result<Self, Self::Error> {
        let server: HostSettings = config.get::<HostSettings>("host")?;
        let cache: CacheSettings = config.get::<CacheSettings>("cache")?;
        Ok(Configuration {
            host: server,
            cache,
        })
    }
}

mod cache;
mod error;
mod protocol;
mod host;
