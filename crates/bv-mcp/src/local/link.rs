//! The vault side of the local gatekeeper: what it needs from a vault, and
//! the request/response shapes of the pairing exchange every host shares.

use serde_json::{json, Map, Value};
use zeroize::{Zeroize, Zeroizing};

use super::operator::{MfaChallenge, MfaFactor};
use crate::{catalogue, pairing::PairingRecord, sanitize::sanitize_for_model};

/// `resources/v2/connect/mfa/begin`, the logical path of the operator's
/// step-up preflight (`features/mcp-brokered-sessions.md` §3.1 step 1).
pub const CONNECT_MFA_BEGIN_PATH: &str = "resources/v2/connect/mfa/begin";
/// `resources/v2/connect/mfa/verify`, which mints the call-bound ticket.
pub const CONNECT_MFA_VERIFY_PATH: &str = "resources/v2/connect/mfa/verify";

/// The one call an operator MFA ticket is for (§3.1 step 3): the vault binds
/// the ticket to these three and refuses it for anything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpCallRef {
    pub pairing_id: String,
    pub tool: String,
    /// `bv_mcp::dispatcher::args_hash` of the call's `arguments`.
    pub args_hash: String,
}

/// What the vault said about a profile's MFA gate, asked as the operator.
#[derive(Clone, Debug, PartialEq)]
pub enum MfaPreflight {
    NotRequired,
    Required(MfaChallenge),
}

/// Why the operator's step-up cannot start for a session call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MfaBeginError {
    /// The vault says this operator cannot complete MFA at all: not a
    /// userpass principal, or no factor enrolled (`mfa_unavailable:`).
    Unavailable(String),
    /// Anything else: unreachable, refused, not found.
    Other(String),
}

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

    /// [`CONNECT_MFA_BEGIN_PATH`] for one profile, as the **operator** --
    /// with the session the pairing tokens are minted from, never an MCP
    /// token. Use [`mfa_begin_body`], [`mfa_preflight_from_begin`] and
    /// [`mfa_begin_error`]. The default cannot ask, so a host that does not
    /// implement it has every session call refused before any prompt.
    fn connect_mfa_begin(&self, resource: &str, profile_id: &str) -> Result<MfaPreflight, MfaBeginError> {
        let _ = (resource, profile_id);
        Err(MfaBeginError::Other("this host cannot ask the vault about the operator's MFA".to_string()))
    }

    /// [`CONNECT_MFA_VERIFY_PATH`] as the operator, with the factor and the
    /// call the ticket is bound to ([`mfa_verify_body`]). Returns the ticket
    /// ([`ticket_from_verify`]), which only the gatekeeper ever holds.
    fn connect_mfa_verify(
        &self,
        resource: &str,
        profile_id: &str,
        factor: &MfaFactor,
        call: &McpCallRef,
    ) -> Result<Zeroizing<String>, String> {
        let _ = (resource, profile_id, factor, call);
        Err("this host cannot verify the operator's MFA".to_string())
    }
}

/// The body of [`CONNECT_MFA_BEGIN_PATH`].
pub fn mfa_begin_body(resource: &str, profile_id: &str) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("resource".into(), Value::String(resource.to_string()));
    body.insert("profile_id".into(), Value::String(profile_id.to_string()));
    body
}

/// The body of [`CONNECT_MFA_VERIFY_PATH`] for an agent call: the factor
/// and the `mcp_call` block that binds the ticket to it. The factor is a
/// one-time code or a single-use assertion; the map is wiped by the caller
/// dropping it as soon as the request is sent.
pub fn mfa_verify_body(resource: &str, profile_id: &str, factor: &MfaFactor, call: &McpCallRef) -> Map<String, Value> {
    let mut body = mfa_begin_body(resource, profile_id);
    body.insert("method".into(), Value::String(factor.method().to_string()));
    match factor {
        MfaFactor::Totp(code) => body.insert("totp_code".into(), Value::String(code.trim().to_string())),
        MfaFactor::Fido2(credential) => body.insert("credential".into(), Value::String(credential.to_string())),
    };
    body.insert(
        "mcp_call".into(),
        json!({ "pairing_id": call.pairing_id, "tool": call.tool, "args_hash": call.args_hash }),
    );
    body
}

/// A logical response's data, whether it arrives bare (in process) or under
/// `data` (HTTP).
fn response_data(answer: &Value) -> &Value {
    answer.get("data").filter(|d| d.is_object()).unwrap_or(answer)
}

/// Reads a begin answer. A gated profile with no usable factor is
/// [`MfaBeginError::Unavailable`]; a malformed answer is refused, never read
/// as "not required".
pub fn mfa_preflight_from_begin(answer: &Value) -> Result<MfaPreflight, MfaBeginError> {
    let data = response_data(answer);
    let required = data
        .get("required")
        .and_then(Value::as_bool)
        .ok_or_else(|| MfaBeginError::Other("the vault's MFA preflight answer carried no `required`".to_string()))?;
    if !required {
        return Ok(MfaPreflight::NotRequired);
    }
    let methods: Vec<String> = data
        .get("methods")
        .and_then(Value::as_array)
        .map(|m| m.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    if methods.is_empty() {
        return Err(MfaBeginError::Unavailable(
            "this connection profile requires your MFA, and your account has no second factor enrolled".to_string(),
        ));
    }
    Ok(MfaPreflight::Required(MfaChallenge { methods, fido2: data.get("fido2").filter(|v| !v.is_null()).cloned() }))
}

/// Classifies a begin refusal by the vault's `mfa_unavailable:` reason.
pub fn mfa_begin_error(message: String) -> MfaBeginError {
    if message.contains("mfa_unavailable:") {
        MfaBeginError::Unavailable(message)
    } else {
        MfaBeginError::Other(message)
    }
}

/// The ticket out of a verify answer. An answer without one is a refusal,
/// never a success with nothing to relay.
pub fn ticket_from_verify(answer: &Value) -> Result<Zeroizing<String>, String> {
    response_data(answer)
        .get("connect_ticket")
        .and_then(Value::as_str)
        .filter(|t| !t.trim().is_empty())
        .map(|t| Zeroizing::new(t.to_string()))
        .ok_or_else(|| "the vault verified the factor but returned no ticket; refusing the call".to_string())
}

/// The body of the `mcp/token` exchange for a local pairing (spec §4,
/// pairing mode): the operator's approved grant, never more. A pairing that
/// may open sessions asserts `confirm_connect: true` -- always, whatever the
/// record says, because confirmation of session calls has no off switch;
/// one that may not sends neither key, as before sessions existed.
pub fn exchange_request_body(record: &PairingRecord, ttl_secs: u64) -> Map<String, Value> {
    let mut pairing = json!({
        "id": record.id,
        "client_name": record.client_name,
        "client_version": record.client_version,
        "tool_allowlist": record.tool_allowlist,
        "path_scope": record.path_scope,
        "reveal_allowed": record.reveal_allowed,
        "destructive_allowed": record.destructive_allowed,
        "ttl_secs": ttl_secs,
    });
    if record.connect_allowed {
        pairing["connect_allowed"] = json!(true);
        pairing["confirm_connect"] = json!(true);
    }
    let mut body = Map::new();
    body.insert("pairing".into(), pairing);
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
            connect_allowed: false,
            confirm_connect: false,
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
        assert!(body["pairing"].get("connect_allowed").is_none(), "no session keys without sessions");
        assert!(body["pairing"].get("confirm_connect").is_none());
    }

    #[test]
    fn a_session_pairing_always_asserts_confirmation_at_exchange() {
        let mut r = record();
        r.connect_allowed = true;
        // Even a record edited to say otherwise cannot turn confirmation off.
        r.confirm_connect = false;
        let body = exchange_request_body(&r, 600);
        assert_eq!(body["pairing"]["connect_allowed"], json!(true));
        assert_eq!(body["pairing"]["confirm_connect"], json!(true));
    }

    fn call() -> McpCallRef {
        McpCallRef { pairing_id: "p1".into(), tool: "bv_resource_ssh_exec".into(), args_hash: "ab".repeat(32) }
    }

    #[test]
    fn the_verify_body_binds_the_factor_to_one_call() {
        let totp = MfaFactor::Totp(Zeroizing::new(" 123456 ".into()));
        let body = mfa_verify_body("web-01", "p_agent", &totp, &call());
        assert_eq!(
            Value::Object(body),
            json!({
                "resource": "web-01", "profile_id": "p_agent", "method": "totp", "totp_code": "123456",
                "mcp_call": { "pairing_id": "p1", "tool": "bv_resource_ssh_exec", "args_hash": "ab".repeat(32) },
            })
        );
        let fido2 = MfaFactor::Fido2(Zeroizing::new("{\"id\":\"x\"}".into()));
        let body = mfa_verify_body("web-01", "p_agent", &fido2, &call());
        assert_eq!((body["method"].as_str(), body["credential"].as_str()), (Some("fido2"), Some("{\"id\":\"x\"}")));
        assert!(body.get("totp_code").is_none());
        assert!(!format!("{totp:?}").contains("123456"), "a factor never prints");
    }

    #[test]
    fn begin_answers_are_read_strictly() {
        let open = json!({ "data": { "required": false, "methods": [] } });
        assert_eq!(mfa_preflight_from_begin(&open), Ok(MfaPreflight::NotRequired));
        let gated = json!({ "required": true, "methods": ["fido2", "totp"], "fido2": { "publicKey": {} } });
        let Ok(MfaPreflight::Required(c)) = mfa_preflight_from_begin(&gated) else { panic!("gated") };
        assert_eq!(c.methods, vec!["fido2".to_string(), "totp".to_string()]);
        assert!(c.fido2.is_some());
        assert!(matches!(
            mfa_preflight_from_begin(&json!({ "required": true, "methods": [] })),
            Err(MfaBeginError::Unavailable(_))
        ));
        assert!(matches!(mfa_preflight_from_begin(&json!({})), Err(MfaBeginError::Other(_))));
        assert!(matches!(
            mfa_begin_error("vault answered HTTP 403: mfa_unavailable: only userpass".into()),
            MfaBeginError::Unavailable(_)
        ));
        assert!(matches!(mfa_begin_error("permission denied".into()), MfaBeginError::Other(_)));
    }

    #[test]
    fn a_verify_answer_without_a_ticket_is_a_refusal() {
        assert_eq!(ticket_from_verify(&json!({ "data": { "connect_ticket": "t" } })).unwrap().as_str(), "t");
        assert_eq!(ticket_from_verify(&json!({ "connect_ticket": "t2" })).unwrap().as_str(), "t2");
        assert!(ticket_from_verify(&json!({ "data": { "connect_ticket": "" } })).is_err());
        assert!(ticket_from_verify(&json!({})).is_err());
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
