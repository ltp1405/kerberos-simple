use config::Config;
use serde::Deserialize;

use crate::server::infra::database::DbSettings;

#[derive(Deserialize, Clone)]
pub struct SqliteDbSettings;

impl DbSettings for SqliteDbSettings {}

impl From<Config> for SqliteDbSettings {
    fn from(config: Config) -> Self {
        let settings = config
            .get::<Self>("sqlite")
            .expect("Failed to load sqlite configuration");
        settings
    }
}
