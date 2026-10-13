//! The vault side of the local gatekeeper: what it needs from a vault, and
//! the request/response shapes of the pairing exchange every host shares.

use serde_json::{json, Map, Value};
use zeroize::Zeroize;

use crate::{catalogue, pairing::PairingRecord, sanitize::sanitize_for_model};

/// An MCP-bound token minted for one pairing. It lives only in the local
/// server's memory: it is never written to disk, never logged (`Debug`
/// redacts it) and is wiped when dropped.
#[derive(Clone)]
pub struct MintedToken {
    pub token: String,
    pub expires_at: u64,
}

impl std::fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedToken").field("token", &"<redacted>").field("expires_at", &self.expires_at).finish()
    }
}

impl Drop for MintedToken {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Debug)]
pub enum ForwardError {
    /// The vault answered 401/403: the token was revoked, expired or refused.
    Refused(u16),
    Other(String),
}

/// What the local server needs from the vault. A trait so the gatekeeping
/// logic is testable without a server, and so each host (the CLI over HTTP,
/// the desktop app over its own connection) supplies its own.
pub trait VaultLink: Send + Sync {
    fn exchange_pairing(&self, record: &PairingRecord, ttl_secs: u64) -> Result<MintedToken, String>;
    fn forward(&self, token: &str, message: &Value) -> Result<Value, ForwardError>;
}

/// The body of the `mcp/token` exchange for a local pairing (spec §4,
/// pairing mode): the operator's approved grant, never more.
pub fn exchange_request_body(record: &PairingRecord, ttl_secs: u64) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert(
        "pairing".into(),
        json!({
            "id": record.id,
            "client_name": record.client_name,
            "client_version": record.client_version,
            "tool_allowlist": record.tool_allowlist,
            "path_scope": record.path_scope,
            "reveal_allowed": record.reveal_allowed,
            "destructive_allowed": record.destructive_allowed,
            "ttl_secs": ttl_secs,
        }),
    );
    body.insert("catalogue_hash".into(), Value::String(catalogue::catalogue_hash()));
    body.insert("ttl_secs".into(), json!(ttl_secs));
    body
}

/// Reads the minted token out of a successful exchange answer. The vault
/// returns it under `auth` (HTTP) or `data.auth` (a logical response); the
/// lease falls back to the requested TTL when the answer does not state one.
pub fn minted_token_from_exchange(data: &Value, ttl_secs: u64, now: u64) -> Result<MintedToken, String> {
    let auth = data.get("auth").or_else(|| data.get("data").and_then(|d| d.get("auth")));
    let auth = auth.ok_or_else(|| "vault exchange response carried no auth block".to_string())?;
    let token = auth
        .get("client_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "vault exchange response carried no token".to_string())?
        .to_string();
    let lease = auth.get("lease_duration").and_then(Value::as_u64).unwrap_or(ttl_secs);
    Ok(MintedToken { token, expires_at: now + lease })
}

/// An operator-readable account of a vault error answer. The vault's own
/// message is sanitized first: it is shown to a model as well as a human.
pub fn vault_error_text(body: &Option<Value>, status: u16) -> String {
    let detail = body
        .as_ref()
        .and_then(|b| b.get("errors").and_then(Value::as_array).and_then(|e| e.first()).and_then(Value::as_str))
        .or_else(|| body.as_ref().and_then(|b| b.get("error")).and_then(Value::as_str));
    match detail {
        Some(d) => format!("vault answered HTTP {status}: {}", sanitize_for_model(d)),
        None => format!("vault answered HTTP {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::Transport;

    fn record() -> PairingRecord {
        PairingRecord {
            version: 1,
            id: "0123456789abcdef0123456789abcdef".into(),
            client_name: "claude-code".into(),
            client_version: "2.1".into(),
            peer_uid: Some(501),
            transport: Transport::Uds.as_str().into(),
            pairing_token_hash: None,
            tool_allowlist: vec!["bv_kv_read_metadata".into()],
            path_scope: vec!["secret/metadata/ai/*".into()],
            reveal_allowed: false,
            destructive_allowed: true,
            confirm_reveal: true,
            confirm_destructive: true,
            ttl_secs: 3600,
            approved_at: 0,
            expires_at: None,
            last_used_at: 0,
        }
    }

    #[test]
    fn the_exchange_body_carries_the_grant_and_the_catalogue_hash() {
        let body = exchange_request_body(&record(), 600);
        assert_eq!(body["pairing"]["id"], json!("0123456789abcdef0123456789abcdef"));
        assert_eq!(body["pairing"]["tool_allowlist"], json!(["bv_kv_read_metadata"]));
        assert_eq!(body["pairing"]["destructive_allowed"], json!(true));
        assert_eq!(body["pairing"]["ttl_secs"], json!(600));
        assert_eq!(body["ttl_secs"], json!(600));
        assert_eq!(body["catalogue_hash"], json!(catalogue::catalogue_hash()));
        // Nothing the vault would treat as an operator decision beyond the grant.
        assert!(body["pairing"].get("confirm_reveal").is_none());
    }

    #[test]
    fn the_minted_token_is_read_from_auth_or_data_auth() {
        let http = json!({ "auth": { "client_token": "t1", "lease_duration": 120 } });
        let minted = minted_token_from_exchange(&http, 600, 1_000).unwrap();
        assert_eq!((minted.token.as_str(), minted.expires_at), ("t1", 1_120));

        let logical = json!({ "data": { "auth": { "client_token": "t2" } } });
        let minted = minted_token_from_exchange(&logical, 600, 1_000).unwrap();
        assert_eq!((minted.token.as_str(), minted.expires_at), ("t2", 1_600), "falls back to the requested TTL");

        assert!(minted_token_from_exchange(&json!({}), 600, 0).is_err());
        assert!(minted_token_from_exchange(&json!({ "auth": { "client_token": "" } }), 600, 0).is_err());
    }

    #[test]
    fn a_minted_token_never_prints() {
        let minted = MintedToken { token: "SECRET-0123456789".into(), expires_at: 7 };
        let shown = format!("{minted:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(shown.contains("expires_at: 7"));
    }

    #[test]
    fn vault_errors_are_sanitized() {
        let body = Some(json!({ "errors": ["\u{1b}[31mpermission denied\u{1b}[0m"] }));
        assert_eq!(vault_error_text(&body, 403), "vault answered HTTP 403: permission denied");
        assert_eq!(vault_error_text(&None, 503), "vault answered HTTP 503");
    }
}
