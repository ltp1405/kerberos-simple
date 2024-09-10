use chrono::{DateTime, Utc};
use secrecy::Secret;

#[derive(Debug)]
pub struct Principal {
    pub pname: String,
    pub realm: String,
    pub flag: u32,
    pub expire: DateTime<Utc>,
}