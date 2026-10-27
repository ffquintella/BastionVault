//! Errors of a dynamic plugin and the status codes they travel as.
//!
//! A plugin reports a failure with a non-zero `done` status (process) or
//! `bv_run` return value (WASM) and an `{"error": "..."}` body. The host
//! answers `502` for any failed dynamic verb and redacts the call's
//! credentials from the message; the SDK redacts them before that too.

use std::fmt;

/// Status codes a dynamic plugin answers with. `0` is success.
pub mod status {
    /// The target system refused or failed the operation.
    pub const TARGET: i32 = 1;
    /// A named record (role, connection) does not exist.
    pub const NOT_FOUND: i32 = 2;
    /// The request was malformed or refused on its merits.
    pub const INVALID: i32 = 3;
    /// The host refused a host call (capability, session, or its merits).
    pub const HOST_REFUSED: i32 = 4;
    /// The host could not serve a host call (pool exhausted, storage).
    pub const UNAVAILABLE: i32 = 5;
    /// The plugin does not implement the operation.
    pub const UNSUPPORTED: i32 = 6;
    /// The host and the plugin disagree on the wire protocol.
    pub const PROTOCOL: i32 = 7;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicError {
    /// The target system failed: SQL error, unreachable server, auth failure.
    Target(String),
    /// A named record does not exist.
    NotFound(String),
    /// The request or the plugin's configuration is not acceptable.
    Invalid(String),
    /// The host refused a capability the manifest does not declare. The host
    /// quarantines a plugin that does this; it is a plugin bug.
    Forbidden(&'static str),
    /// A dynamic host call outside a dynamic-secret RPC.
    NoSession(&'static str),
    /// The host refused a host call on its merits (`invalid: …`).
    HostRefused(String),
    /// The host could not serve a host call (`unavailable: …`, storage).
    Unavailable(String),
    /// The plugin does not implement the operation.
    Unsupported(&'static str),
    /// A malformed message from the host.
    Protocol(String),
    /// Rotate-root on a host that set the new secret: this plugin ran to the
    /// end and did not store it. The reply says so (`root_stored: false`), the
    /// only answer on which the host puts the previous secret back; any other
    /// failure leaves it unknown which secret was stored.
    RootNotStored(String),
}

impl DynamicError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }

    pub fn target(msg: impl Into<String>) -> Self {
        Self::Target(msg.into())
    }

    /// The status the plugin answers with.
    pub fn status(&self) -> i32 {
        match self {
            Self::Target(_) => status::TARGET,
            Self::NotFound(_) => status::NOT_FOUND,
            Self::Invalid(_) => status::INVALID,
            Self::Forbidden(_) | Self::NoSession(_) | Self::HostRefused(_) => status::HOST_REFUSED,
            Self::Unavailable(_) | Self::RootNotStored(_) => status::UNAVAILABLE,
            Self::Unsupported(_) => status::UNSUPPORTED,
            Self::Protocol(_) => status::PROTOCOL,
        }
    }

    /// A short label for diagnostics: never carries request data.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Target(_) => "target",
            Self::NotFound(_) => "not_found",
            Self::Invalid(_) => "invalid",
            Self::Forbidden(_) => "forbidden",
            Self::NoSession(_) => "no_session",
            Self::HostRefused(_) => "host_refused",
            Self::Unavailable(_) => "unavailable",
            Self::Unsupported(_) => "unsupported",
            Self::Protocol(_) => "protocol",
            Self::RootNotStored(_) => "root_not_stored",
        }
    }

    /// Map a process-runtime `host_reply.error` string. The strings are the
    /// server's (`process_runtime::handle_host_call`, `DynamicCallError`).
    pub fn from_process_reply(method: &'static str, error: &str) -> Self {
        match error {
            "forbidden" => Self::Forbidden(method),
            "no_session" => Self::NoSession(method),
            "not_found" => Self::NotFound(method.to_string()),
            other => {
                if let Some(m) = other.strip_prefix("invalid: ") {
                    Self::HostRefused(format!("{method}: {m}"))
                } else if let Some(m) = other.strip_prefix("unavailable: ") {
                    Self::Unavailable(format!("{method}: {m}"))
                } else {
                    Self::Unavailable(format!("{method}: host answered `{other}`"))
                }
            }
        }
    }

    /// Map a negative WASM return code of a `bv.dynamic_*` import.
    pub fn from_wasm_code(method: &'static str, code: i32) -> Self {
        match code {
            -2 => Self::Forbidden(method),
            -8 => Self::NoSession(method),
            -4 => Self::HostRefused(format!("{method}: refused by the host")),
            -5 => Self::Unavailable(format!("{method}: the host could not serve it")),
            -3 => Self::Protocol(format!("{method}: reply larger than the plugin's buffer")),
            other => Self::Unavailable(format!("{method}: host returned {other}")),
        }
    }
}

impl fmt::Display for DynamicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(m) => write!(f, "target error: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::Invalid(m) => write!(f, "invalid: {m}"),
            Self::Forbidden(m) => write!(f, "{m} is not declared in the plugin manifest"),
            Self::NoSession(m) => write!(f, "{m} called outside a dynamic-secret call"),
            Self::HostRefused(m) => write!(f, "host refused {m}"),
            Self::Unavailable(m) => write!(f, "host unavailable: {m}"),
            Self::Unsupported(m) => write!(f, "{m} is not supported by this plugin"),
            Self::Protocol(m) => write!(f, "protocol error: {m}"),
            Self::RootNotStored(m) => write!(f, "the new root secret was not stored: {m}"),
        }
    }
}

impl std::error::Error for DynamicError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_reply_strings_map_to_kinds() {
        let m = "dynamic_pool_checkout";
        assert_eq!(DynamicError::from_process_reply(m, "forbidden"), DynamicError::Forbidden(m));
        assert_eq!(DynamicError::from_process_reply(m, "no_session"), DynamicError::NoSession(m));
        assert!(
            matches!(DynamicError::from_process_reply(m, "invalid: no such connection"), DynamicError::HostRefused(s) if s.contains("no such connection"))
        );
        assert!(matches!(
            DynamicError::from_process_reply(m, "unavailable: pool exhausted"),
            DynamicError::Unavailable(_)
        ));
        assert!(matches!(DynamicError::from_process_reply(m, "internal"), DynamicError::Unavailable(_)));
    }

    #[test]
    fn wasm_codes_map_to_kinds() {
        let m = "dynamic_lease_register";
        assert_eq!(DynamicError::from_wasm_code(m, -2), DynamicError::Forbidden(m));
        assert_eq!(DynamicError::from_wasm_code(m, -8), DynamicError::NoSession(m));
        assert_eq!(DynamicError::from_wasm_code(m, -4).status(), status::HOST_REFUSED);
        assert_eq!(DynamicError::from_wasm_code(m, -5).status(), status::UNAVAILABLE);
        assert_eq!(DynamicError::from_wasm_code(m, -3).status(), status::PROTOCOL);
    }

    #[test]
    fn every_error_is_a_non_zero_status() {
        for e in [
            DynamicError::target("x"),
            DynamicError::NotFound("x".into()),
            DynamicError::invalid("x"),
            DynamicError::Forbidden("m"),
            DynamicError::NoSession("m"),
            DynamicError::HostRefused("x".into()),
            DynamicError::Unavailable("x".into()),
            DynamicError::Unsupported("op"),
            DynamicError::Protocol("x".into()),
            DynamicError::RootNotStored("x".into()),
        ] {
            assert_ne!(e.status(), 0, "{e}");
        }
    }
}
