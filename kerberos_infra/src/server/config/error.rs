use config::ConfigError;

pub enum StartupError {
    PathNotFound,
    KeyNotFound,
}

impl From<ConfigError> for StartupError {
    fn from(value: ConfigError) -> Self {
        match value {
            ConfigError::NotFound(_) => StartupError::KeyNotFound,
            _ => StartupError::PathNotFound,
        }
    }
}
