use config::{Config, ConfigError};
use messages::{Decode, EncAsRepPart};
use std::convert::identity;
use std::fs;
use std::path::PathBuf;

struct AppConfig {
    cache_location: PathBuf,
}

impl AppConfig {
    pub fn init(config_path: String) -> Result<crate::config::AppConfig, ConfigError> {
        let cfg = Config::builder()
            .add_source(config::File::with_name(&config_path))
            .build()?;

        let cfg = cfg.try_deserialize()?;
        Ok(cfg)
    }
}

pub struct ListTicketHandler {
    cache_location: PathBuf,
}

impl Default for ListTicketHandler {
    fn default() -> Self {
        Self {
            cache_location: PathBuf::from("./"),
        }
    }
}

impl ListTicketHandler {
    fn open_file_and_read(
        &self,
        folder_name: Option<&str>,
        name: &str,
    ) -> std::io::Result<Vec<u8>> {
        let mut loc = self.cache_location.clone();
        match folder_name {
            None => {}
            Some(folder) => {
                loc.push(folder);
                fs::create_dir_all(loc.clone())?;
            }
        }
        loc.push(name);
        fs::read(loc)
    }
    pub fn list_tickets(&self) -> Vec<EncAsRepPart> {
        let mut loc = self.cache_location.clone();
        loc.push("enc_as_rep_part");

        let entries: Vec<_> = fs::read_dir(loc).unwrap().filter_map(Result::ok).collect();
        entries
            .iter()
            .filter_map(|entry| {
                let path = entry.path();
                if let Some(file_name) = path.file_name() {
                    let b = self
                        .open_file_and_read(Some("enc_as_rep_part"), file_name.to_str().unwrap())
                        .unwrap();
                    Some(EncAsRepPart::from_der(&b).unwrap())
                } else {
                    None
                }
            })
            .collect()
    }
}
