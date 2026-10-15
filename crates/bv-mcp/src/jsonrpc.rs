//! JSON-RPC 2.0 envelope and the MCP 2026-07-28 `_meta` shapes this crate
//! needs. Deliberately a small hand-written subset, not the official Rust
//! MCP SDK — see features/mcp-access.md § Dependencies for why.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0".to_string(), id, result: Some(result), error: None }
    }

    pub fn failure(id: Value, error: JsonRpcError) -> Self {
        Self { jsonrpc: "2.0".to_string(), id, result: None, error: Some(error) }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), data: None }
    }

    pub fn with_data_code(code: i64, message: impl Into<String>, data_code: &str) -> Self {
        Self { code, message: message.into(), data: Some(serde_json::json!({ "code": data_code })) }
    }
}

/// `resultType` on a `tools/call` response: `complete` is a normal answer,
/// `input_required` is MRTR — the client must re-submit with a confirmed
/// `requestState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultType {
    Complete,
    InputRequired,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub result_type: ResultType,
    pub content: Vec<ContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_state: Option<String>,
    #[serde(default)]
    pub is_error: bool,
}

impl CallToolResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            result_type: ResultType::Complete,
            content: vec![ContentBlock::text(text)],
            structured_content: None,
            request_state: None,
            is_error: false,
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            result_type: ResultType::Complete,
            content: vec![ContentBlock::text(text)],
            structured_content: None,
            request_state: None,
            is_error: true,
        }
    }

    pub fn input_required(text: impl Into<String>, request_state: String) -> Self {
        Self {
            result_type: ResultType::InputRequired,
            content: vec![ContentBlock::text(text)],
            structured_content: None,
            request_state: Some(request_state),
            is_error: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text { text: String },
}

impl ContentBlock {
    pub fn text(text: impl Into<String>) -> Self {
        ContentBlock::Text { text: text.into() }
    }
}

/// Parsed `_meta["io.modelcontextprotocol/*"]` fields this crate reads from
/// a request or writes onto a response.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RequestMeta {
    #[serde(rename = "io.modelcontextprotocol/protocolVersion", default)]
    pub protocol_version: Option<String>,
    #[serde(rename = "io.modelcontextprotocol/clientInfo", default)]
    pub client_info: Option<ClientInfo>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// The `_meta` key under which the local gatekeeper asserts that the operator
/// confirmed a call (`features/mcp-brokered-sessions.md` §9). Every
/// `io.bastionvault/*` key is the gatekeeper's: it strips any a client sent
/// before adding its own.
pub const OPERATOR_CONFIRMATION_META_KEY: &str = "io.bastionvault/confirmation";

/// The gatekeeper's confirmation record:
/// `{"by": "operator", "at": <unix seconds>, "mfa": <bool>}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct OperatorConfirmation {
    pub by: String,
    pub at: u64,
    #[serde(default)]
    pub mfa: bool,
}

/// The confirmation record in a call's `params._meta`, when it is well
/// formed and says `by: "operator"`. Anything else — absent, another `by`,
/// a mistyped field — is no confirmation, and does not disturb the rest of
/// `_meta`'s parsing. The vault cannot see the confirmation happen: this is
/// the local host's assertion, and is audited as such.
pub fn operator_confirmation(meta: Option<&Value>) -> Option<OperatorConfirmation> {
    let record = meta?.get(OPERATOR_CONFIRMATION_META_KEY)?;
    let confirmation: OperatorConfirmation = serde_json::from_value(record.clone()).ok()?;
    (confirmation.by == "operator").then_some(confirmation)
}

/// The `_meta` key under which the local gatekeeper relays the operator's
/// connect MFA ticket for one session call (`features/mcp-brokered-sessions.md`
/// §3.1 step 4). Never in `arguments`, which the ticket is bound to by hash;
/// never shown to the MCP client, which never sees a relayed request.
pub const CONNECT_TICKET_META_KEY: &str = "io.bastionvault/connect_ticket";

/// Longest ticket the vault reads from `_meta`. A minted ticket is 43
/// characters (32 random bytes, base64url); anything far longer is not one.
pub const MAX_CONNECT_TICKET_LEN: usize = 128;

/// The relayed connect MFA ticket in a call's `params._meta`, when it is a
/// non-empty string of plausible length. The vault, not this parse, decides
/// whether it is valid: it redeems it single-use against the call.
pub fn connect_ticket(meta: Option<&Value>) -> Option<&str> {
    let ticket = meta?.get(CONNECT_TICKET_META_KEY)?.as_str()?.trim();
    (!ticket.is_empty() && ticket.len() <= MAX_CONNECT_TICKET_LEN).then_some(ticket)
}

#[cfg(test)]
mod confirmation_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_well_formed_operator_record_is_a_confirmation() {
        let meta = json!({ "io.bastionvault/confirmation": { "by": "operator", "at": 1_760_000_000u64, "mfa": true } });
        assert_eq!(
            operator_confirmation(Some(&meta)),
            Some(OperatorConfirmation { by: "operator".into(), at: 1_760_000_000, mfa: true })
        );
        let no_mfa = json!({ "io.bastionvault/confirmation": { "by": "operator", "at": 5 } });
        assert!(operator_confirmation(Some(&no_mfa)).is_some_and(|c| !c.mfa));
        for not_one in [
            json!({}),
            json!({ "io.bastionvault/confirmation": { "by": "agent", "at": 5 } }),
            json!({ "io.bastionvault/confirmation": { "by": "operator", "at": "yesterday" } }),
            json!({ "io.bastionvault/confirmation": { "by": "operator" } }),
            json!({ "io.bastionvault/confirmation": true }),
        ] {
            assert_eq!(operator_confirmation(Some(&not_one)), None, "{not_one}");
        }
        assert_eq!(operator_confirmation(None), None);
    }

    #[test]
    fn only_a_plausible_string_is_a_relayed_ticket() {
        let meta = json!({ "io.bastionvault/connect_ticket": " abc " });
        assert_eq!(connect_ticket(Some(&meta)), Some("abc"));
        for not_one in [
            json!({}),
            json!({ "io.bastionvault/connect_ticket": "" }),
            json!({ "io.bastionvault/connect_ticket": 7 }),
            json!({ "io.bastionvault/connect_ticket": "x".repeat(MAX_CONNECT_TICKET_LEN + 1) }),
        ] {
            assert_eq!(connect_ticket(Some(&not_one)), None, "{not_one}");
        }
        assert_eq!(connect_ticket(None), None);
    }
}
