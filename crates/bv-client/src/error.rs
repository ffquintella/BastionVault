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

    /// The previously-selected cluster node is no longer reachable
    /// or serviceable (transport failure, TLS handshake fail, sealed
    /// 5xx, etc.). The caller's sticky session is over — the
    /// expected recovery is for the operator to trigger a fresh
    /// `connect`, which re-runs discovery + health and picks a new
    /// node. We deliberately do NOT auto-retry against another node
    /// from inside the request path; see the feature spec's
    /// "Sticky session with failover-on-next-open" section.
    #[error("node `{host}` is unavailable: {reason}")]
    NodeUnavailable { host: String, reason: String },

    /// The response body was larger than the client's configured
    /// read limit (see `RemoteBackendBuilder::with_max_response_bytes`).
    /// Deliberately *not* a `NodeUnavailable`: the node answered
    /// correctly, and neither retrying it nor failing over to a
    /// sibling can change the outcome — the body is simply too big
    /// for this client to buffer. Keeping the two apart is what stops
    /// an oversized response from lighting up the reconnect UX and
    /// re-downloading the body from a second node.
    #[error("response body is larger than the client limit of {limit} bytes")]
    ResponseTooLarge { limit: u64 },

    /// Discovery + health probing found zero healthy candidates.
    /// Distinct from `NodeUnavailable` (which signals an in-session
    /// failure of a previously-good node) so the connect path can
    /// surface a different operator message.
    #[error("no healthy node found for `{cluster}`: {reason}")]
    NoHealthyNode { cluster: String, reason: String },
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

    pub fn node_unavailable<H: Into<String>, R: Into<String>>(host: H, reason: R) -> Self {
        ClientError::NodeUnavailable {
            host: host.into(),
            reason: reason.into(),
        }
    }

    pub fn no_healthy_node<C: Into<String>, R: Into<String>>(cluster: C, reason: R) -> Self {
        ClientError::NoHealthyNode {
            cluster: cluster.into(),
            reason: reason.into(),
        }
    }

    /// True when the error is an oversized response body rather than
    /// a node or protocol failure.
    pub fn is_response_too_large(&self) -> bool {
        matches!(self, ClientError::ResponseTooLarge { .. })
    }

    /// True when the error indicates the previously-pinned cluster
    /// node went away (transport failure, TLS issue, etc.). Callers
    /// use this to decide whether to surface a "reconnect" UX rather
    /// than a generic error toast.
    pub fn is_node_unavailable(&self) -> bool {
        matches!(self, ClientError::NodeUnavailable { .. })
    }
}

/// Map a body-read failure into a [`ClientError`], translating ureq's
/// `BodyExceedsLimit` into the explicit [`ClientError::ResponseTooLarge`].
/// Every body read in this crate goes through here so an oversized
/// response reports the limit it hit instead of masquerading as a
/// transport error (which `classify_node_failure` would then fold into
/// `NodeUnavailable`).
pub fn map_body_read(err: ureq::Error, limit: u64) -> ClientError {
    match err {
        // The payload carries the limit ureq was handed, which is the
        // same value we configured — report ours so the message names
        // the knob the operator can change.
        ureq::Error::BodyExceedsLimit(_) => ClientError::ResponseTooLarge { limit },
        other => ClientError::Ureq(other),
    }
}

/// Classify a transport-level error and an HTTP response body as
/// either "the node went away" (yielding `NodeUnavailable`) or
/// something else (passthrough). Used by `RemoteBackend::handle` to
/// enforce the sticky-session failure contract from the feature spec.
pub fn classify_node_failure(host: &str, raw: ClientError) -> ClientError {
    match &raw {
        // An oversized body is the node answering *correctly* with
        // more bytes than we agreed to buffer. Defensive: read sites
        // already translate this via `map_body_read`, but a raw
        // `Ureq(BodyExceedsLimit)` reaching here must never become
        // `NodeUnavailable` — that would trigger a failover retry that
        // re-downloads the same too-large body from another node.
        ClientError::Ureq(ureq::Error::BodyExceedsLimit(limit)) => {
            ClientError::ResponseTooLarge { limit: *limit }
        }
        // ureq transport failures are the textbook "node went away":
        // connection refused, TLS handshake fail, DNS hiccup, etc.
        ClientError::Ureq(_) | ClientError::Io(_) => {
            ClientError::node_unavailable(host, raw.to_string())
        }
        // A 5xx Server error with a sealed-shaped body counts too —
        // the node is technically up but is no longer serving.
        ClientError::Server { status, message } if *status >= 500 => {
            let msg_lc = message.to_ascii_lowercase();
            if msg_lc.contains("sealed")
                || msg_lc.contains("uninitialized")
                || msg_lc.contains("standby")
            {
                ClientError::node_unavailable(host, message)
            } else {
                raw
            }
        }
        _ => raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_classified_as_node_unavailable() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let mapped = classify_node_failure("vault.example", ClientError::Io(io));
        assert!(mapped.is_node_unavailable());
    }

    #[test]
    fn server_503_with_sealed_body_classified() {
        let raw = ClientError::server(503, "Vault is sealed");
        let mapped = classify_node_failure("vault.example", raw);
        assert!(mapped.is_node_unavailable());
    }

    #[test]
    fn server_500_with_unrelated_body_passes_through() {
        let raw = ClientError::server(500, "internal error");
        let mapped = classify_node_failure("vault.example", raw);
        assert!(!mapped.is_node_unavailable());
        assert!(matches!(mapped, ClientError::Server { status: 500, .. }));
    }

    #[test]
    fn server_4xx_never_classified_as_node_unavailable() {
        // 4xx is the caller's fault, not the node's. Folding it into
        // NodeUnavailable would mislead the "reconnect" UX.
        let raw = ClientError::server(403, "permission denied");
        let mapped = classify_node_failure("vault.example", raw);
        assert!(!mapped.is_node_unavailable());
    }

    /// Regression: a recording larger than the read limit used to be
    /// classified as `NodeUnavailable`, so the GUI reported "node
    /// `https://…:5200` is unavailable" for a node that was perfectly
    /// healthy — and the failover path then re-fetched the same body
    /// from a sibling.
    #[test]
    fn body_exceeds_limit_is_not_node_unavailable() {
        let raw = ClientError::Ureq(ureq::Error::BodyExceedsLimit(10 * 1024 * 1024));
        let mapped = classify_node_failure("vault.example", raw);
        assert!(!mapped.is_node_unavailable());
        assert!(mapped.is_response_too_large());
        assert!(matches!(
            mapped,
            ClientError::ResponseTooLarge { limit } if limit == 10 * 1024 * 1024
        ));
    }

    #[test]
    fn map_body_read_reports_configured_limit() {
        let mapped = map_body_read(ureq::Error::BodyExceedsLimit(7), 128 * 1024 * 1024);
        assert!(matches!(
            mapped,
            ClientError::ResponseTooLarge { limit } if limit == 128 * 1024 * 1024
        ));
        // Anything else stays a transport error, so the sticky-session
        // classification still sees it.
        let other = map_body_read(ureq::Error::HostNotFound, 1);
        assert!(classify_node_failure("vault.example", other).is_node_unavailable());
    }

    #[test]
    fn backend_error_passes_through() {
        let raw = ClientError::backend("internal misuse");
        let mapped = classify_node_failure("vault.example", raw);
        assert!(matches!(mapped, ClientError::Backend(_)));
    }
}
