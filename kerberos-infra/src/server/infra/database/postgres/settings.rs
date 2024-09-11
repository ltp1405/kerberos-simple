use config::Config;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use serde_aux::field_attributes::deserialize_number_from_string;
use sqlx::postgres::{PgConnectOptions, PgSslMode};

use crate::server::infra::database::DbSettings;

#[derive(Deserialize, Clone)]
pub struct PgDbSettings {
    pub username: String,
    pub host: String,
    pub password: Secret<String>,
    pub name: Secret<String>,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub require_ssl: bool,
}

impl PgDbSettings {
    pub fn without_db(&self) -> PgConnectOptions {
        let mode = if self.require_ssl {
            PgSslMode::Require
        } else {
            PgSslMode::Prefer
        };
        PgConnectOptions::new()
            .host(&self.host)
            .username(&self.username)
            .password(self.password.expose_secret())
            .port(self.port)
            .ssl_mode(mode)
    }
    pub fn with_db(&self) -> PgConnectOptions {
        let options = self.without_db();
        options.database(self.name.expose_secret())
    }
}

impl DbSettings for PgDbSettings {}

impl From<Config> for PgDbSettings {
    fn from(config: Config) -> Self {
        let settings = config
            .get::<Self>("postgres")
            .expect("Failed to load postgres configuration");
        settings
    }
}
