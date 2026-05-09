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
    ///
    /// The server speaks two body shapes:
    /// 1. *Envelope* — `{"data": {...}, "auth": {...}, "warnings": [...]}`
    ///    used by `response_logical` (the `/v1/{path}` catch-all
    ///    handler).
    /// 2. *Raw* — the response's `data` map serialized at the top
    ///    level, e.g. `{"secret": {...}, "auth": {...}}` from
    ///    `sys/internal/ui/mounts`. This is what `http::handle_request`
    ///    emits for the dedicated sys handlers.
    ///
    /// We detect the envelope shape by the presence of a top-level
    /// `"data"` key, OR an `"auth"` value that looks like a login
    /// payload (`{"client_token": "..."}`). Otherwise, treat the whole
    /// object as the `data` field — a raw sys response like
    /// `{"secret": ..., "auth": ...mounts}` then lands in `out.data`
    /// where consumers expect it, instead of being shredded across
    /// the envelope fields.
    pub fn from_json(value: Value) -> Self {
        let mut out = JsonResponse::default();
        let Value::Object(mut obj) = value else {
            return out;
        };

        let auth_is_login = obj.get("auth").map(is_login_auth).unwrap_or(false);
        let is_envelope = obj.contains_key("data") || auth_is_login;

        if !is_envelope {
            // Raw shape: the entire body is the response's data map.
            // Don't touch any other "envelope" keys — they're real
            // data fields that happen to share names.
            out.data = Some(obj);
            return out;
        }

        if let Some(Value::Object(data)) = obj.remove("data") {
            out.data = Some(data);
        }
        if let Some(auth) = obj.remove("auth") {
            if !auth.is_null() && is_login_auth(&auth) {
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

/// A login-style `auth` payload always carries a `client_token`. The
/// `sys/internal/ui/mounts` response also has an `"auth"` key, but
/// that one is a *map of auth-mount entries*, not a login payload —
/// telling them apart by this single field keeps `from_json` from
/// mis-routing mount data into [`JsonResponse::auth`].
fn is_login_auth(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.contains_key("client_token"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_json_envelope_with_data() {
        let r = JsonResponse::from_json(json!({
            "data": {"keys": ["a", "b"]},
            "warnings": ["w1"],
        }));
        assert!(r.data.as_ref().unwrap().contains_key("keys"));
        assert!(r.auth.is_none());
        assert_eq!(r.warnings, vec!["w1".to_string()]);
    }

    #[test]
    fn from_json_login_envelope() {
        let r = JsonResponse::from_json(json!({
            "auth": {"client_token": "tok", "policies": ["root"]},
        }));
        assert!(r.auth.is_some());
        assert!(r.data.is_none());
    }

    #[test]
    fn from_json_raw_sys_internal_ui_mounts() {
        // Server's `http::handle_request` emits the response's data
        // map at the top level for dedicated sys handlers. The
        // `auth` key here is a map of auth-mount entries, not a
        // login payload — it must land in `data`, not `auth`.
        let r = JsonResponse::from_json(json!({
            "secret": {"secret/": {"type": "kv-v2"}},
            "auth": {"token/": {"type": "token"}},
        }));
        let data = r.data.expect("raw body should populate data");
        assert!(data.contains_key("secret"));
        assert!(data.contains_key("auth"));
        assert!(r.auth.is_none(), "mount-map auth must not be treated as login");
    }
}
