//! The one error type of this crate, and how it reaches an HTTP caller.

use bv_errors::RvError;

use crate::template::TemplateError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DynamicError {
    /// A statement template or a value substituted into one was refused.
    #[error("statement template refused: {0}")]
    Template(#[from] TemplateError),
    /// The operating system's random source failed. Never retried with a
    /// weaker source.
    #[error("the operating system random source failed: {0}")]
    Entropy(String),
    /// A caller- or plugin-supplied value is malformed.
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    /// Every connection slot for the target is checked out.
    #[error("connection pool for `{0}` is exhausted")]
    PoolExhausted(String),
    /// The pool knows no target by that name.
    #[error("no connection named `{0}` is configured")]
    UnknownConnection(String),
    /// Opening or validating a target connection failed.
    #[error("connection to `{connection}` failed: {reason}")]
    Connect { connection: String, reason: String },
    /// A host connector's statement execution on the target failed.
    #[error("host execution on the target failed: {0}")]
    Execute(String),
    /// A persisted record has a format this host does not read.
    #[error("unsupported {record} format version {version}")]
    UnsupportedVersion { record: &'static str, version: u32 },
}

impl DynamicError {
    pub fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid { field, reason: reason.into() }
    }

    /// HTTP status an operator sees for this error.
    pub fn status(&self) -> u16 {
        match self {
            Self::Template(_) | Self::Invalid { .. } => 400,
            Self::UnknownConnection(_) => 404,
            Self::PoolExhausted(_) => 503,
            Self::Connect { .. } | Self::Execute(_) => 502,
            Self::Entropy(_) | Self::UnsupportedVersion { .. } => 500,
        }
    }
}

impl From<DynamicError> for RvError {
    fn from(e: DynamicError) -> Self {
        RvError::ErrResponseStatus(e.status(), e.to_string())
    }
}
