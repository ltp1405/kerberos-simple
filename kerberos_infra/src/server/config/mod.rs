use config::Config;
use error::StartupError;

pub use cache::CacheSettings;
pub use host::HostSettings;

use super::utils::Environment;

pub use protocol::Protocol;

pub struct Configuration {
    pub cache: CacheSettings,
    pub host: HostSettings,
}

impl Configuration {
    pub fn load_from_dir() -> Result<Self, StartupError> {
        let builder = prepare("server");

        builder.build()?.try_into()
    }

    pub fn load(dir: &str) -> Result<Self, StartupError> {
        let builder = prepare(dir);

        builder.build()?.try_into()
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
mod host;
mod protocol;
