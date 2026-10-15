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
    #[error("backend error: {0}")]
    Backend(String),
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
            McpError::Backend(_) => "mcp_backend_error",
        }
    }

    pub fn jsonrpc_code(&self) -> i64 {
        match self {
            McpError::InvalidArgument(_) => JSONRPC_INVALID_PARAMS,
            McpError::Backend(_) | McpError::ResultTooLarge { .. } => JSONRPC_INTERNAL_ERROR,
            _ => JSONRPC_INVALID_PARAMS,
        }
    }
}
