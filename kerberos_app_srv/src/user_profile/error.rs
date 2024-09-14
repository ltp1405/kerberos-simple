pub enum AppServerHandlerError {
    InvalidCredentials,
    UserIsNotAuthorized,
    UserProfileNotFound,
    InternalServerError,
}

impl std::fmt::Display for AppServerHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AppServerHandlerError::InvalidCredentials => write!(f, "Invalid credentials"),
            AppServerHandlerError::UserProfileNotFound => write!(f, "User not found"),
            AppServerHandlerError::InternalServerError => write!(f, "Internal server error"),
            AppServerHandlerError::UserIsNotAuthorized => write!(f, "User is not authorized"),
        }
    }
}
