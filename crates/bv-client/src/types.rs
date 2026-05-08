//! Wire-level types: the JSON-serializable subset of the server's
//! `logical::Response` that the GUI actually consumes, plus the
//! `Operation` enum used to dispatch a request through the
//! [`Backend`](crate::Backend) trait.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Logical operation. Mirrors `bastion_vault::logical::Operation` but
/// is defined here so client consumers don't need to depend on the
/// server crate. Values map to HTTP methods inside `RemoteBackend`
/// and are matched directly inside `EmbeddedBackend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    Read,
    Write,
    Delete,
    List,
}

/// The shape of a logical response as it crosses a process boundary
/// (HTTP for `RemoteBackend`, the Tauri command return for the GUI).
///
/// This is intentionally a flat, JSON-friendly subset of the server's
/// `logical::Response` — only the fields the GUI's command layer
/// actually reads. Lease/auth metadata that today flows through HTTP
/// headers and cookies stays in `data`/`auth` here as plain JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsonResponse {
    /// `data` payload from the server (whatever the engine returned
    /// under `data:` in the JSON body — the GUI commands index into
    /// this with `.get("keys")`, `.get("role_id")`, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Map<String, Value>>,
    /// `auth` payload (login responses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Value>,
    /// Lease metadata for dynamic secrets responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_duration: Option<u64>,
    /// Warnings the server attached to a successful response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Redirect target (some auth flows return a 307-style redirect
    /// hint here rather than as an HTTP redirect).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub redirect: String,
}

impl JsonResponse {
    /// Build a response from a parsed JSON body. Pulls out the
    /// well-known top-level keys the BastionVault HTTP API uses and
    /// drops anything else on the floor — the GUI only reads these.
    pub fn from_json(value: Value) -> Self {
        let mut out = JsonResponse::default();
        let Value::Object(mut obj) = value else {
            return out;
        };
        if let Some(Value::Object(data)) = obj.remove("data") {
            out.data = Some(data);
        }
        if let Some(auth) = obj.remove("auth") {
            if !auth.is_null() {
                out.auth = Some(auth);
            }
        }
        if let Some(Value::String(s)) = obj.remove("lease_id") {
            if !s.is_empty() {
                out.lease_id = Some(s);
            }
        }
        if let Some(Value::Bool(b)) = obj.remove("renewable") {
            out.renewable = Some(b);
        }
        if let Some(Value::Number(n)) = obj.remove("lease_duration") {
            if let Some(u) = n.as_u64() {
                out.lease_duration = Some(u);
            }
        }
        if let Some(Value::Array(arr)) = obj.remove("warnings") {
            out.warnings = arr
                .into_iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect();
        }
        if let Some(Value::String(s)) = obj.remove("redirect") {
            out.redirect = s;
        }
        out
    }
}
