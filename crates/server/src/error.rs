#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing or invalid API key")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Invalid(String),
    #[error("too many requests")]
    RateLimited,
    /// Never shown to callers: the detail goes to the server log only.
    #[error("internal error")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Unauthorized => "unauthorized",
            Error::Forbidden(_) => "forbidden",
            Error::NotFound => "not_found",
            Error::Conflict(_) => "conflict",
            Error::Invalid(_) => "invalid",
            Error::RateLimited => "rate_limited",
            Error::Internal(_) => "internal",
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Internal(format!("database: {e}"))
    }
}

impl From<twof_core::canonical::CanonError> for Error {
    fn from(e: twof_core::canonical::CanonError) -> Self {
        Error::Invalid(e.to_string())
    }
}

impl From<twof_core::action::ActionError> for Error {
    fn from(e: twof_core::action::ActionError) -> Self {
        Error::Invalid(e.to_string())
    }
}
