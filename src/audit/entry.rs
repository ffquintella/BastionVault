//! Audit entry schema + redaction.
//!
//! An `AuditEntry` is a JSON-serializable record of one operation,
//! stamped with the preceding entry's hash so the trail is
//! tamper-evident. Sensitive fields (tokens, request body, response
//! data) are passed through `hmac_redact` before serialization so
//! devices persist only `hmac:<hex>` digests, not the raw values.

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::{
    errors::RvError,
    logical::{Operation, Request, Response},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditEntry {
    /// RFC3339 timestamp (UTC).
    pub time: String,
    /// `"request"` — entry logged before dispatch — or `"response"`
    /// — entry logged after the backend returned.
    pub r#type: String,
    #[serde(default)]
    pub auth: AuditAuth,
    #[serde(default)]
    pub request: AuditRequest,
    /// Only populated on response entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<AuditResponse>,
    /// Populated on response entries when the backend returned an
    /// error. Empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// Hex SHA-256 of the previous entry's serialized form, or
    /// `"sha256:" + zero-hash` for the chain genesis.
    #[serde(default)]
    pub prev_hash: String,
    /// Multi-tenancy: the namespace the request's token is bound to
    /// (`""` = root). Lets a per-namespace auditor (and the root SOC
    /// mirror) attribute every event to a tenant. Empty for legacy /
    /// root / unauthenticated requests.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditAuth {
    /// HMAC of the client token — enough to correlate entries from
    /// the same token without exposing the token itself.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub metadata: Map<String, Value>,
    /// Derived client address (after walking trusted-proxy XFF/Forwarded
    /// headers, falls back to the socket peer). This is the field
    /// downstream consumers should treat as "the requester's IP."
    /// Kept under the original name for backwards compatibility with
    /// existing log shippers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_address: String,
    /// Socket-level peer (string form, with port). What `getpeername`
    /// returned at accept time — this is the proxy's address when a
    /// reverse proxy is in front of us. Always recorded so a reviewer
    /// can distinguish "the proxy attested X originating from Y" from
    /// "the socket reported Y directly." See
    /// `features/packaging-podman-server.md` § Client IP visibility.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_address_socket: String,
    /// Derived client IP (no port). Equals `remote_address` for
    /// requests that go through a trusted proxy, and equals the socket
    /// peer's IP for direct-exposure requests.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_address_derived: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditRequest {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    pub operation: String,
    pub path: String,
    /// Redacted copy of the request body. `null`/absent when no body
    /// was sent or when the device is configured to omit data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Derived client address — see `AuditAuth.remote_address`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_address_socket: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_address_derived: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditResponse {
    /// Redacted response data. Empty for operations that don't
    /// return data (writes, deletes) or when the device opts out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub redirect: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl AuditEntry {
    /// Build a `request` entry from the outgoing `Request`. `hmac_key`
    /// is used to redact the client token and request body values.
    /// `log_raw` disables redaction (dev/debug only).
    pub fn from_request(req: &Request, hmac_key: &[u8], log_raw: bool) -> Self {
        let socket_addr = req
            .connection
            .as_ref()
            .map(|c| c.peer_addr.clone())
            .unwrap_or_default();
        // Phase 1.5: prefer the derived address (after trusted-proxy
        // resolution) when present. Falls back to the socket peer for
        // back-compat with pre-1.5 entries and for code paths that
        // don't construct a Connection (e.g. internal-only requests).
        let derived_addr = req
            .connection
            .as_ref()
            .map(|c| c.peer_addr_derived.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| socket_addr.clone());

        let auth = AuditAuth {
            client_token: if req.client_token.is_empty() {
                String::new()
            } else if log_raw {
                req.client_token.clone()
            } else {
                format!("hmac:{}", hmac_redact(hmac_key, req.client_token.as_bytes()))
            },
            display_name: req.auth.as_ref().map(|a| a.display_name.clone()).unwrap_or_default(),
            policies: req.auth.as_ref().map(|a| a.policies.clone()).unwrap_or_default(),
            metadata: req
                .auth
                .as_ref()
                .map(|a| {
                    a.metadata
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                        .collect()
                })
                .unwrap_or_default(),
            remote_address: derived_addr.clone(),
            remote_address_socket: socket_addr.clone(),
            remote_address_derived: derived_addr.clone(),
        };

        let namespace = req
            .auth
            .as_ref()
            .and_then(|a| {
                a.metadata
                    .get(crate::modules::namespace::token_binding::NS_PATH_META)
                    .cloned()
            })
            .unwrap_or_default();

        Self {
            time: Utc::now().to_rfc3339(),
            r#type: "request".to_string(),
            auth,
            namespace,
            request: AuditRequest {
                id: req.id.clone(),
                operation: operation_str(req.operation).to_string(),
                path: req.path.clone(),
                data: redact_body(req.body.as_ref(), hmac_key, log_raw),
                remote_address: derived_addr.clone(),
                remote_address_socket: socket_addr,
                remote_address_derived: derived_addr,
            },
            response: None,
            error: String::new(),
            prev_hash: String::new(),
        }
    }

    /// Build a `response` entry from a completed `(Request, Response)`
    /// pair, or from a request + error string on failure.
    pub fn from_response(
        req: &Request,
        resp: &Option<Response>,
        error: Option<&str>,
        hmac_key: &[u8],
        log_raw: bool,
    ) -> Self {
        let mut entry = Self::from_request(req, hmac_key, log_raw);
        entry.r#type = "response".to_string();
        if let Some(r) = resp {
            entry.response = Some(AuditResponse {
                data: redact_body(r.data.as_ref(), hmac_key, log_raw),
                redirect: r.redirect.clone(),
                warnings: r.warnings.clone(),
            });
        }
        if let Some(e) = error {
            entry.error = e.to_string();
        }
        entry
    }
}

/// Return the hex SHA-256 digest of `data` keyed by `key`.
pub fn hmac_redact(key: &[u8], data: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Serialize the entry to a single compact JSON line (no trailing
/// newline) — what the file device writes to disk and what the hash
/// chain digests.
pub fn serialize_line(entry: &AuditEntry) -> Result<String, RvError> {
    Ok(serde_json::to_string(entry)?)
}

fn operation_str(op: Operation) -> &'static str {
    match op {
        Operation::Read => "read",
        Operation::Write => "write",
        Operation::Delete => "delete",
        Operation::List => "list",
        Operation::Renew => "renew",
        Operation::Revoke => "revoke",
        Operation::Rollback => "rollback",
        Operation::Help => "help",
    }
}

/// Walk a JSON body and replace every leaf string value with its
/// HMAC digest. `Null`, booleans, and numbers are left alone — they
/// don't carry secrets directly and keeping them preserves the
/// shape of the entry for operators reading the log. When `log_raw`
/// is true the body is returned verbatim.
fn redact_body(
    body: Option<&Map<String, Value>>,
    hmac_key: &[u8],
    log_raw: bool,
) -> Option<Value> {
    let body = body?;
    if body.is_empty() {
        return None;
    }
    if log_raw {
        return Some(Value::Object(body.clone()));
    }
    let redacted: Map<String, Value> = body
        .iter()
        .map(|(k, v)| (k.clone(), redact_value(v, hmac_key)))
        .collect();
    Some(Value::Object(redacted))
}

fn redact_value(v: &Value, hmac_key: &[u8]) -> Value {
    match v {
        Value::String(s) if s.is_empty() => Value::String(String::new()),
        Value::String(s) => Value::String(format!("hmac:{}", hmac_redact(hmac_key, s.as_bytes()))),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), redact_value(v, hmac_key)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|v| redact_value(v, hmac_key)).collect()),
        // Numbers, booleans, null pass through — not secret-bearing.
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_string_values_deep() {
        let key = b"k";
        let mut body = Map::new();
        body.insert("password".into(), Value::String("hunter2".into()));
        body.insert(
            "nested".into(),
            Value::Object({
                let mut m = Map::new();
                m.insert("token".into(), Value::String("t".into()));
                m.insert("n".into(), Value::Number(42.into()));
                m
            }),
        );
        let out = redact_body(Some(&body), key, false).unwrap();
        let o = out.as_object().unwrap();
        assert!(o["password"].as_str().unwrap().starts_with("hmac:"));
        let n = o["nested"].as_object().unwrap();
        assert!(n["token"].as_str().unwrap().starts_with("hmac:"));
        assert_eq!(n["n"].as_u64().unwrap(), 42);
    }

    #[test]
    fn log_raw_disables_redaction() {
        let key = b"k";
        let mut body = Map::new();
        body.insert("password".into(), Value::String("plaintext".into()));
        let out = redact_body(Some(&body), key, true).unwrap();
        assert_eq!(out["password"].as_str().unwrap(), "plaintext");
    }

    #[test]
    fn entry_carries_peer_addr_from_connection() {
        use crate::logical::{Connection, Operation, Request};
        let mut req = Request::new("secret/foo");
        req.operation = Operation::Read;
        let mut conn = Connection::default();
        conn.peer_addr = "203.0.113.42:54321".to_string();
        req.connection = Some(conn);

        let entry = AuditEntry::from_request(&req, b"k", false);
        // Direct exposure (no derived addr set): both fields equal the
        // socket peer.
        assert_eq!(entry.auth.remote_address, "203.0.113.42:54321");
        assert_eq!(entry.request.remote_address, "203.0.113.42:54321");
        assert_eq!(entry.auth.remote_address_socket, "203.0.113.42:54321");
        assert_eq!(entry.auth.remote_address_derived, "203.0.113.42:54321");
    }

    #[test]
    fn entry_distinguishes_socket_and_derived_when_proxied() {
        use crate::logical::{Connection, Operation, Request};
        let mut req = Request::new("secret/foo");
        req.operation = Operation::Read;
        let mut conn = Connection::default();
        conn.peer_addr = "10.0.0.5:443".to_string(); // edge proxy
        conn.peer_addr_derived = "203.0.113.7".to_string(); // real client
        req.connection = Some(conn);

        let entry = AuditEntry::from_request(&req, b"k", false);
        // The "primary" remote_address is the derived one.
        assert_eq!(entry.auth.remote_address, "203.0.113.7");
        assert_eq!(entry.request.remote_address, "203.0.113.7");
        // Both views are preserved separately so a reviewer can tell
        // proxy from origin.
        assert_eq!(entry.auth.remote_address_socket, "10.0.0.5:443");
        assert_eq!(entry.auth.remote_address_derived, "203.0.113.7");
        assert_eq!(entry.request.remote_address_socket, "10.0.0.5:443");
        assert_eq!(entry.request.remote_address_derived, "203.0.113.7");
    }

    #[test]
    fn entry_remote_address_empty_when_no_connection() {
        use crate::logical::{Operation, Request};
        let mut req = Request::new("secret/foo");
        req.operation = Operation::Read;
        // req.connection stays None — e.g. internal/synthetic call.

        let entry = AuditEntry::from_request(&req, b"k", false);
        assert!(entry.auth.remote_address.is_empty());
        assert!(entry.request.remote_address.is_empty());
        assert!(entry.auth.remote_address_socket.is_empty());
        assert!(entry.auth.remote_address_derived.is_empty());
    }
}
