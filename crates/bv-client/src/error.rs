//! Slim error type for the client crate. Deliberately *not* a clone
//! of `bastion_vault::errors::RvError` — we want consumers (the GUI's
//! Tauri command layer in particular) to be able to map this onto
//! their own error type without dragging the server's enum surface
//! into their dep graph.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("http: {0}")]
    Http(#[from] http::Error),

    #[error("ureq: {0}")]
    Ureq(#[from] ureq::Error),

    /// HTTP-level failure: the server returned a status the client
    /// considers an error and the body parsed (or didn't) into a
    /// best-effort message.
    #[error("HTTP {status}: {message}")]
    Server { status: u16, message: String },

    /// TLS material on disk couldn't be parsed or the configured
    /// combination is invalid (e.g. client cert without key).
    #[error("tls: {0}")]
    Tls(String),

    /// Catch-all for backend-specific failures bubbling out of an
    /// embedded adapter (the GUI's `EmbeddedBackend` will use this
    /// when wrapping a `bastion_vault::errors::RvError`).
    #[error("backend: {0}")]
    Backend(String),
}

impl ClientError {
    pub fn server<M: Into<String>>(status: u16, message: M) -> Self {
        ClientError::Server { status, message: message.into() }
    }

    pub fn backend<M: Into<String>>(msg: M) -> Self {
        ClientError::Backend(msg.into())
    }

    pub fn tls<M: Into<String>>(msg: M) -> Self {
        ClientError::Tls(msg.into())
    }
}
