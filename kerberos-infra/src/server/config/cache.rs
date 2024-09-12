use std::num::NonZeroUsize;

use serde::Deserialize;
use serde_aux::field_attributes::deserialize_number_from_string;

#[derive(Deserialize, Clone)]
pub struct CacheSettings {
    pub capacity: NonZeroUsize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub ttl: u64,
}
