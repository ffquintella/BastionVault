//! `data.code` strings for `tools/call` JSON-RPC errors, plus the JSON-RPC
//! numeric codes the 2026-07-28 spec allocates.

use thiserror::Error;

/// JSON-RPC `-32020`: `Mcp-Method`/`Mcp-Name` header mismatch.
pub const JSONRPC_HEADER_MISMATCH: i64 = -32020;
/// JSON-RPC `-32022`: unsupported (legacy) protocol version.
pub const JSONRPC_UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
/// Generic JSON-RPC invalid-params code.
pub const JSONRPC_INVALID_PARAMS: i64 = -32602;
/// Generic JSON-RPC internal-error code.
pub const JSONRPC_INTERNAL_ERROR: i64 = -32603;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum McpError {
    #[error("tool `{0}` is not in the catalogue")]
    UnknownTool(String),
    #[error("tool `{0}` is not in this principal's allow-list")]
    ToolNotAllowed(String),
    #[error("path `{0}` is outside this principal's scope")]
    PathOutOfScope(String),
    #[error("reveal was requested but this principal cannot reveal values")]
    RevealDenied,
    #[error("this principal cannot call destructive tools")]
    DestructiveDenied,
    #[error("confirmation required before this call can proceed")]
    ConfirmationRequired,
    #[error("the confirmation token is invalid, expired, or already used")]
    ConfirmationInvalid,
    #[error("rate limit exceeded for this tool")]
    RateLimited,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// A session tool on a binding without `connect_allowed` (or, for a
    /// forged or truncated binding, without `confirm_connect`).
    /// `features/mcp-brokered-sessions.md` §3 step 2.2.
    #[error("this principal's binding does not allow brokered sessions (connect_allowed)")]
    ConnectNotAllowed,
    /// A session tool on an app (network-mode) binding. Permanent: there is
    /// no operator to confirm the call. §3 step 2.3.
    #[error("brokered sessions need a local pairing with an operator to confirm each call; network-mode apps never open them")]
    ConnectRequiresLocalOperator,
    /// A shaped session result over its ceiling (`bv_mcp::untrusted`, §8
    /// step 6). The per-stream caps bound a result, so this means they did
    /// not hold; refused rather than truncated after the fact.
    #[error("the result is {bytes} bytes, over this call's {limit}-byte ceiling")]
    ResultTooLarge { bytes: usize, limit: usize },
    /// A brokered-session handler (`resources/v2/connect/agent/*`) refused
    /// or failed the call with one of [`SESSION_ERROR_CODES`]. The code is
    /// taken only from that fixed list, never from free text, so a client can
    /// match on it; `message` is the handler's own operator-facing reason,
    /// which never carries output, credential material or a ticket.
    #[error("{message}")]
    Session { code: &'static str, message: String },
    #[error("backend error: {0}")]
    Backend(String),
}

/// The stable codes a session handler answers with
/// (`features/mcp-brokered-sessions.md` §4, plus the generic gates it
/// re-checks). The handler leads its error message with one of them, then
/// `": "`; [`session_error_from_backend`] finds it.
pub const SESSION_ERROR_CODES: &[&str] = &[
    "mcp_connect_not_allowed",
    "mcp_connect_requires_local_operator",
    "mcp_confirmation_required",
    "mcp_invalid_argument",
    "mcp_brokered_sessions_disabled",
    "mcp_session_protocol_disabled",
    "mcp_session_profile_not_agent_enabled",
    "agent_policy_invalid",
    "mcp_session_mfa_required",
    "mcp_session_mfa_unavailable",
    // The relayed operator ticket was unknown, spent, expired or bound to
    // another call, operator, pairing, resource or profile (§3.1 step 5).
    "mcp_session_mfa_ticket_refused",
    "mcp_session_requires_bastion",
    "mcp_session_login_class_unsupported",
    "mcp_session_destination_refused",
    "mcp_session_host_key_unpinned",
    "mcp_session_host_key_mismatch",
    "mcp_rate_limited",
    "mcp_session_busy",
    "mcp_session_timeout",
    "mcp_session_aborted",
    "mcp_session_failed",
    "mcp_web_login_mode_unsupported",
    "mcp_web_origin_refused",
    // Web (§6.3 "TLS"): the target's certificate is not trusted by the
    // platform roots and the profile pins nothing (no trust-on-first-use, no
    // "accept anyway" for an agent), or the profile pins keys and none
    // admits it.
    "mcp_web_tls_unpinned",
    "mcp_web_tls_pin_mismatch",
];

/// A session handler's error, as it reaches the dispatcher through the
/// `Backend` (wrapped in the vault's own error text), mapped back to its
/// stable code. `None` when the message carries no code from
/// [`SESSION_ERROR_CODES`] — a permission denial from the ACL, say — which
/// the caller reports as a plain backend error.
pub fn session_error_from_backend(message: &str) -> Option<McpError> {
    // The vault prefixes a status error ("…, response text: <code>: …"); the
    // handler's own text starts at the code. The earliest code wins, so a
    // code quoted later in a reason cannot replace the one that leads it.
    let mut found: Option<(usize, &'static str)> = None;
    for code in SESSION_ERROR_CODES {
        let marker = format!("{code}: ");
        let mut from = 0;
        while let Some(rel) = message[from..].find(&marker) {
            let at = from + rel;
            let starts_a_word = !message[..at].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_');
            if starts_a_word {
                if found.is_none_or(|(best, _)| at < best) {
                    found = Some((at, code));
                }
                break;
            }
            from = at + marker.len();
        }
    }
    found.map(|(at, code)| McpError::Session { code, message: message[at..].to_string() })
}

impl McpError {
    /// The stable `data.code` string an MCP client can match on. Never
    /// changes across releases without a catalogue-hash bump.
    pub fn code(&self) -> &'static str {
        match self {
            McpError::UnknownTool(_) => "mcp_unknown_tool",
            McpError::ToolNotAllowed(_) => "mcp_tool_not_allowed",
            McpError::PathOutOfScope(_) => "mcp_path_out_of_scope",
            McpError::RevealDenied => "mcp_reveal_denied",
            McpError::DestructiveDenied => "mcp_destructive_denied",
            McpError::ConfirmationRequired => "mcp_confirmation_required",
            McpError::ConfirmationInvalid => "mcp_confirmation_required",
            McpError::RateLimited => "mcp_rate_limited",
            McpError::InvalidArgument(_) => "mcp_invalid_argument",
            McpError::ConnectNotAllowed => "mcp_connect_not_allowed",
            McpError::ConnectRequiresLocalOperator => "mcp_connect_requires_local_operator",
            McpError::ResultTooLarge { .. } => "mcp_result_too_large",
            McpError::Session { code, .. } => code,
            McpError::Backend(_) => "mcp_backend_error",
        }
    }

    pub fn jsonrpc_code(&self) -> i64 {
        match self {
            McpError::InvalidArgument(_) => JSONRPC_INVALID_PARAMS,
            McpError::Backend(_) | McpError::ResultTooLarge { .. } => JSONRPC_INTERNAL_ERROR,
            McpError::Session { code, .. }
                if matches!(*code, "mcp_session_failed" | "mcp_session_timeout" | "mcp_session_aborted") =>
            {
                JSONRPC_INTERNAL_ERROR
            }
            _ => JSONRPC_INVALID_PARAMS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_code_is_found_behind_the_vault_wrapper_and_nothing_else_is_a_code() {
        let wrapped = "backend: Some error happend, status: 403, response text: \
                       mcp_session_destination_refused: 127.0.0.1 is a loopback address";
        let err = session_error_from_backend(wrapped).unwrap();
        assert_eq!(err.code(), "mcp_session_destination_refused");
        assert_eq!(err.to_string(), "mcp_session_destination_refused: 127.0.0.1 is a loopback address");
        assert_eq!(err.jsonrpc_code(), JSONRPC_INVALID_PARAMS);

        let failed = session_error_from_backend("mcp_session_failed: authentication was refused").unwrap();
        assert_eq!((failed.code(), failed.jsonrpc_code()), ("mcp_session_failed", JSONRPC_INTERNAL_ERROR));

        // Free text is not a code, and a code embedded in a longer word is not one.
        assert!(session_error_from_backend("backend: permission denied").is_none());
        assert!(session_error_from_backend("x_mcp_session_busy: nope").is_none());
        assert!(session_error_from_backend("mcp_made_up_code: nope").is_none());

        // The leading code wins over one quoted later in the reason.
        let quoted = session_error_from_backend("mcp_session_failed: the target said mcp_session_busy: x").unwrap();
        assert_eq!(quoted.code(), "mcp_session_failed");
    }
}
