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
