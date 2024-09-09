use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct ClientEnvError {
    pub(crate) message: String,
}

impl Display for ClientEnvError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientEnvError: {}", self.message)
    }
}

impl Error for ClientEnvError {}
