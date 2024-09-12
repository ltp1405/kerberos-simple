use serde::Deserialize;

#[derive(Clone)]
pub enum Protocol {
    Udp,
    Tcp,
}

impl Protocol {
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::Udp => "udp",
            Protocol::Tcp => "tcp",
        }
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D>(deserializer: D) -> Result<Protocol, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "udp" => Ok(Protocol::Udp),
            "tcp" => Ok(Protocol::Tcp),
            _ => Err(serde::de::Error::custom(format!("This protocol is not supported: {}", value))),
        }
    }
}
