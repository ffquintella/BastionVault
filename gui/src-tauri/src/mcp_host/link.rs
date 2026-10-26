//! The vault side of the GUI-hosted MCP server: the desktop app's own
//! connection, embedded or remote, bound to the one vault session the
//! server was started under.
//!
//! * **Remote** -- the same two HTTP calls `bvault mcp serve` makes, over the
//!   connected `api::Client`: `POST /v2/mcp/token` to mint (so the server's
//!   `mcp.enabled` and TLS gates apply) and `POST /v2/mcp` to forward.
//! * **Embedded** -- the exchange is the ordinary logical write
//!   `sys/mcp/token` through the session's backend, and a forward is answered
//!   in process by `bastion_vault::mcp_endpoint`, the code behind `/v2/mcp`.
//!
//! Every call first checks that the session is still the one the server was
//! started for (same mode, same vault, same token). If it is not -- signed
//! out, locked, another vault -- the call is refused and the server is
//! stopped: a server never carries one session's token to another vault, or
//! mints from a session that has ended. Approvals are a different matter:
//! a pairing is per client, uid and transport (as the CLI's are), not per
//! vault, so an approved client is served under whichever session the app
//! later runs -- within that session's own policies. The consent dialog says
//! which vault is asking.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bastion_vault::{
    core::Core,
    errors::RvError,
    mcp_endpoint::{handle_jsonrpc, McpEndpoint, McpEndpointOutcome},
};
use bv_client::{Backend, Operation};
use bv_mcp::{
    local::{
        exchange_request_body, mfa_begin_body, mfa_begin_error, mfa_preflight_from_begin, mfa_verify_body,
        minted_token_from_exchange, operator_namespace_from_lookup, ticket_from_verify, vault_error_text, ForwardError,
        McpCallRef, MfaBeginError, MfaFactor, MfaPreflight, MintedToken, VaultLink, CONNECT_MFA_BEGIN_PATH,
        CONNECT_MFA_VERIFY_PATH, NAMESPACE_HEADER, TOKEN_LOOKUP_SELF_PATH,
    },
    pairing::{hash_token, new_pairing_token, now_secs, PairingRecord},
    request_state::SingleUseGuard,
    sanitize::sanitize_for_model,
};
use serde_json::{Map, Value};
use tauri::{AppHandle, Manager};
use zeroize::{Zeroize, Zeroizing};

use crate::state::{AppState, VaultMode};

/// Same default the vault's `/v2/mcp` applies (`mcp.tool_timeout_secs`).
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);
pub const SESSION_ENDED: &str =
    "the BastionVault session this server was started under has ended (signed out, locked or switched vault)";

/// Which vault session a running server belongs to: the mode, *which* vault
/// (the remote address, or the identity of the open embedded vault), and a
/// hash of the session token -- never the token. A session token is never
/// sent anywhere but the vault it was read with.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionFingerprint {
    pub mode: VaultMode,
    pub vault: String,
    pub token_hash: String,
}

impl SessionFingerprint {
    pub fn of(mode: VaultMode, vault: String, token: &str) -> Self {
        Self { mode, vault, token_hash: hash_token(token) }
    }
}

fn remote_identity(client: &bastion_vault::api::Client) -> String {
    format!("remote:{}", client.address)
}

fn embedded_identity(vault: &Arc<bastion_vault::BastionVault>) -> String {
    // The open vault's allocation, alive for as long as `AppState` holds it:
    // closing and opening a vault (even the same one) is a new session.
    format!("embedded:{:p}", Arc::as_ptr(vault))
}

/// The live session as `AppState` holds it now: its fingerprint, the token,
/// and how to reach its vault. `None` when no session is unlocked.
pub async fn current_session(state: &AppState) -> Option<(SessionFingerprint, SessionSnapshot)> {
    let token = state.token.lock().await.clone().filter(|t| !t.is_empty()).map(Zeroizing::new)?;
    let mode = state.mode.lock().await.clone();
    let (vault, route) = match mode {
        VaultMode::Remote => {
            let client = state.remote_client.lock().await.clone()?;
            (remote_identity(&client), VaultRoute::Remote(client))
        }
        VaultMode::Embedded => {
            let vault = state.vault.lock().await.clone()?;
            let backend = state.backend.lock().await.clone()?;
            (embedded_identity(&vault), VaultRoute::Embedded { core: vault.core.load_full(), backend })
        }
    };
    let fingerprint = SessionFingerprint::of(mode, vault, &token);
    Some((fingerprint, SessionSnapshot { token, route }))
}

pub enum VaultRoute {
    Remote(bastion_vault::api::Client),
    Embedded { core: Arc<Core>, backend: Arc<dyn Backend> },
}

/// The live session, re-read from `AppState` for each call.
pub struct SessionSnapshot {
    pub token: Zeroizing<String>,
    pub route: VaultRoute,
}

/// Reads the app's session from a connection thread (never from an async
/// task: it blocks on the runtime).
pub struct SessionGuard {
    pub app: AppHandle,
    pub fingerprint: SessionFingerprint,
}

impl SessionGuard {
    pub fn snapshot(&self) -> Result<SessionSnapshot, String> {
        let state = self.app.state::<AppState>();
        match tauri::async_runtime::block_on(current_session(&state)) {
            Some((fingerprint, snapshot)) if fingerprint == self.fingerprint => Ok(snapshot),
            _ => Err(SESSION_ENDED.to_string()),
        }
    }

    pub fn is_current(&self) -> bool {
        self.snapshot().is_ok()
    }
}

/// The `requestState` key for in-process dispatch. Process-local, as the
/// server's is; per-call confirmation happens in the gatekeeper, so the
/// dispatcher never mints one here.
fn request_state_key() -> &'static [u8] {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(new_pairing_token).as_bytes()
}

fn single_use_guard() -> &'static SingleUseGuard {
    static GUARD: OnceLock<SingleUseGuard> = OnceLock::new();
    GUARD.get_or_init(SingleUseGuard::new)
}

fn server_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| env!("CARGO_PKG_VERSION").splitn(3, '.').take(2).collect::<Vec<_>>().join("."))
}

pub struct GuiVaultLink {
    pub session: Arc<SessionGuard>,
    /// The namespace the session's token is bound to, once asked. A server
    /// serves one session (same token, see [`SessionGuard`]) and a token's
    /// binding never changes, so one answer holds; a failure is not cached.
    pub operator_namespace: Mutex<Option<String>>,
    /// The last failure an operator should see in Settings. Sanitized vault
    /// messages only; never a token.
    pub last_error: Arc<Mutex<Option<String>>>,
    /// Called once the session is found to have ended.
    pub on_session_ended: Box<dyn Fn() + Send + Sync>,
}

impl GuiVaultLink {
    fn session(&self) -> Result<SessionSnapshot, String> {
        self.session.snapshot().inspect_err(|_| (self.on_session_ended)())
    }

    fn note<T>(&self, result: Result<T, String>) -> Result<T, String> {
        if let Err(e) = &result {
            *self.last_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.clone());
        }
        result
    }

    /// The namespace the operator's session is bound to (`""` = root), from
    /// the vault's own record of the session's token, never from the MCP
    /// client (`features/mcp-namespace-selection.md` Phase 1). Not the
    /// window's namespace picker: pairing tokens follow the token's binding.
    fn session_namespace(&self) -> Result<String, String> {
        if let Some(ns) = self.operator_namespace.lock().unwrap_or_else(|p| p.into_inner()).clone() {
            return Ok(ns);
        }
        let session = self.session()?;
        let ns = operator_namespace_from_lookup(&operator_call(
            &session,
            Operation::Read,
            TOKEN_LOOKUP_SELF_PATH,
            None,
            "",
        )?)?;
        *self.operator_namespace.lock().unwrap_or_else(|p| p.into_inner()) = Some(ns.clone());
        Ok(ns)
    }

    /// A logical write as the operator -- the session the server was
    /// started under, never an MCP token -- in `namespace`: where the
    /// pairing's token runs, as its exchange reported, else the session's
    /// own. Used for the operator's MFA step-up (§3.1 of
    /// `features/mcp-brokered-sessions.md`); the ticket goes to the gatekeeper.
    fn operator_write(&self, namespace: Option<&str>, path: &str, body: Map<String, Value>) -> Result<Value, String> {
        let namespace = match namespace {
            Some(ns) => ns.to_string(),
            None => self.session_namespace()?,
        };
        let session = self.session()?;
        operator_call(&session, Operation::Write, path, Some(body), &namespace)
    }
}

/// One logical call as the session's operator, in `namespace` (`""` = root,
/// sent without a header).
fn operator_call(
    session: &SessionSnapshot,
    operation: Operation,
    path: &str,
    body: Option<Map<String, Value>>,
    namespace: &str,
) -> Result<Value, String> {
    match &session.route {
        VaultRoute::Remote(client) => operator_call_remote(client, &session.token, operation, path, body, namespace),
        VaultRoute::Embedded { backend, .. } => tauri::async_runtime::block_on(operator_call_embedded(
            backend.as_ref(),
            &session.token,
            operation,
            path,
            body,
            namespace,
        )),
    }
}

fn operator_call_remote(
    client: &bastion_vault::api::Client,
    token: &str,
    operation: Operation,
    path: &str,
    body: Option<Map<String, Value>>,
    namespace: &str,
) -> Result<Value, String> {
    let mut client = client.clone().with_token(token);
    if !namespace.is_empty() {
        client = client.add_header(NAMESPACE_HEADER, namespace);
    }
    let answer = match operation {
        Operation::Read => client.logical().read(path),
        _ => client.logical().write(path, body),
    };
    client.token.zeroize();
    let resp = answer.map_err(|e| format!("could not reach the vault: {e}"))?;
    if resp.response_status != 200 {
        return Err(vault_error_text(&resp.response_data, resp.response_status));
    }
    Ok(resp.response_data.unwrap_or(Value::Null))
}

async fn operator_call_embedded(
    backend: &dyn Backend,
    token: &str,
    operation: Operation,
    path: &str,
    body: Option<Map<String, Value>>,
    namespace: &str,
) -> Result<Value, String> {
    let namespace = (!namespace.is_empty()).then_some(namespace);
    match backend.handle_with_namespace(operation, path, body, token, namespace).await {
        Err(e) => Err(sanitize_for_model(&e.to_string())),
        Ok(resp) => Ok(Value::Object(resp.and_then(|r| r.data).unwrap_or_default())),
    }
}

impl VaultLink for GuiVaultLink {
    fn exchange_pairing(
        &self,
        record: &PairingRecord,
        ttl_secs: u64,
        namespace: Option<&str>,
    ) -> Result<MintedToken, String> {
        let session = self.session()?;
        let body = exchange_request_body(record, ttl_secs, namespace);
        let result = match session.route {
            VaultRoute::Remote(client) => {
                let mut client = client.with_token(&session.token);
                let answer = client.request_write("v2/mcp/token", Some(body));
                client.token.zeroize();
                match answer {
                    Err(e) => Err(format!("could not reach the vault: {e}")),
                    Ok(resp) if resp.response_status != 200 => {
                        Err(vault_error_text(&resp.response_data, resp.response_status))
                    }
                    Ok(resp) => resp
                        .response_data
                        .ok_or_else(|| "vault returned an empty exchange response".to_string())
                        .and_then(|data| minted_token_from_exchange(&data, ttl_secs, now_secs())),
                }
            }
            VaultRoute::Embedded { backend, .. } => {
                let answer = tauri::async_runtime::block_on(backend.handle_with_namespace(
                    Operation::Write,
                    "sys/mcp/token",
                    Some(body),
                    &session.token,
                    None,
                ));
                match answer {
                    Err(e) => Err(format!("the vault refused the exchange: {e}")),
                    Ok(None) => Err("vault returned an empty exchange response".to_string()),
                    Ok(Some(resp)) => {
                        let data = Value::Object(resp.data.unwrap_or_default());
                        minted_token_from_exchange(&data, ttl_secs, now_secs())
                    }
                }
            }
        };
        self.note(result)
    }

    fn forward(&self, token: &str, message: &Value) -> Result<Value, ForwardError> {
        let session = self.session().map_err(ForwardError::Other)?;
        let result = match session.route {
            VaultRoute::Remote(client) => {
                let Some(body) = message.as_object().cloned() else {
                    return Err(ForwardError::Other("only JSON objects can be forwarded".to_string()));
                };
                let mut client = client.with_token(token);
                let answer = client.request_write("v2/mcp", Some(body));
                client.token.zeroize();
                match answer {
                    Err(e) => Err(ForwardError::Other(format!("could not reach the vault: {e}"))),
                    Ok(resp) => match (resp.response_status, resp.response_data) {
                        (200, Some(v)) => Ok(v),
                        (s @ (401 | 403), _) => Err(ForwardError::Refused(s)),
                        (s, data) => Err(ForwardError::Other(vault_error_text(&data, s))),
                    },
                }
            }
            VaultRoute::Embedded { core, .. } => forward_in_process(&core, token, message),
        };
        if let Err(ForwardError::Other(e)) = &result {
            let _ = self.note::<()>(Err(e.clone()));
        }
        result
    }

    fn connect_mfa_begin(
        &self,
        namespace: Option<&str>,
        resource: &str,
        profile_id: &str,
    ) -> Result<MfaPreflight, MfaBeginError> {
        let answer = self.operator_write(namespace, CONNECT_MFA_BEGIN_PATH, mfa_begin_body(resource, profile_id));
        mfa_preflight_from_begin(&answer.map_err(mfa_begin_error)?)
    }

    fn connect_mfa_verify(
        &self,
        namespace: Option<&str>,
        resource: &str,
        profile_id: &str,
        factor: &MfaFactor,
        call: &McpCallRef,
    ) -> Result<Zeroizing<String>, String> {
        let answer = self.operator_write(
            namespace,
            CONNECT_MFA_VERIFY_PATH,
            mfa_verify_body(resource, profile_id, factor, call),
        )?;
        ticket_from_verify(&answer)
    }

    fn operator_namespace(&self) -> Option<String> {
        self.session_namespace().ok()
    }
}

/// `/v2/mcp`, answered in process for an embedded vault.
fn forward_in_process(core: &Arc<Core>, token: &str, message: &Value) -> Result<Value, ForwardError> {
    let body = serde_json::to_vec(message).map_err(|e| ForwardError::Other(e.to_string()))?;
    let endpoint = McpEndpoint {
        core,
        // No network peer: a CIDR-bound token is refused rather than given an
        // invented address, as every other in-process privileged path does.
        client_ip: "",
        tool_timeout: TOOL_TIMEOUT,
        server_version: server_version(),
        request_state_key: request_state_key(),
        single_use_guard: single_use_guard(),
    };
    match tauri::async_runtime::block_on(handle_jsonrpc(&endpoint, token, &body)) {
        Ok(McpEndpointOutcome::Answer(response)) => {
            serde_json::to_value(response).map_err(|e| ForwardError::Other(e.to_string()))
        }
        Ok(McpEndpointOutcome::BadRequest(message)) => Err(ForwardError::Other(message)),
        Ok(McpEndpointOutcome::Unauthorized(_)) => Err(ForwardError::Refused(401)),
        // `check_token` refusing the token (revoked, expired, not MCP-bound)
        // is the in-process 403; the gatekeeper drops it and re-mints.
        Err(RvError::ErrPermissionDenied) => Err(ForwardError::Refused(403)),
        Err(e) => Err(ForwardError::Other(format!("the vault could not answer: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    //! T457: the operator's step-up calls carry the namespace the operator's
    //! own session is bound to. The embedded half, against a fake backend
    //! that records what it was asked; the remote half sends the same value
    //! through `api::Client::add_header`, exercised by the CLI's link tests.

    use bv_client::{ClientError, JsonResponse};
    use serde_json::json;

    use super::*;

    type Call = (Operation, String, Option<String>, String);

    #[derive(Default)]
    struct Recording {
        calls: Mutex<Vec<Call>>,
    }

    #[async_trait::async_trait]
    impl Backend for Recording {
        async fn handle(
            &self,
            operation: Operation,
            path: &str,
            body: Option<Map<String, Value>>,
            token: &str,
        ) -> Result<Option<JsonResponse>, ClientError> {
            self.handle_with_namespace(operation, path, body, token, None).await
        }

        async fn handle_with_namespace(
            &self,
            operation: Operation,
            path: &str,
            _body: Option<Map<String, Value>>,
            token: &str,
            namespace: Option<&str>,
        ) -> Result<Option<JsonResponse>, ClientError> {
            self.calls.lock().unwrap().push((operation, path.to_string(), namespace.map(str::to_string), token.into()));
            let data = if path == TOKEN_LOOKUP_SELF_PATH {
                json!({ "meta": { "namespace_path": "tenant-a" } })
            } else {
                json!({ "required": false, "methods": [] })
            };
            Ok(Some(JsonResponse { data: data.as_object().cloned(), ..Default::default() }))
        }
    }

    #[tokio::test]
    async fn an_embedded_step_up_is_sent_in_the_sessions_namespace() {
        let backend = Recording::default();
        let lookup = operator_call_embedded(&backend, "op-token", Operation::Read, TOKEN_LOOKUP_SELF_PATH, None, "")
            .await
            .unwrap();
        let ns = operator_namespace_from_lookup(&lookup).unwrap();
        assert_eq!(ns, "tenant-a");
        operator_call_embedded(&backend, "op-token", Operation::Write, CONNECT_MFA_BEGIN_PATH, Some(Map::new()), &ns)
            .await
            .unwrap();
        operator_call_embedded(&backend, "op-token", Operation::Write, CONNECT_MFA_BEGIN_PATH, Some(Map::new()), "")
            .await
            .unwrap();

        let calls = backend.calls.lock().unwrap();
        assert_eq!(calls[0].2, None, "the lookup itself is not namespaced");
        assert_eq!((calls[1].1.as_str(), calls[1].2.as_deref()), (CONNECT_MFA_BEGIN_PATH, Some("tenant-a")));
        assert_eq!(calls[2].2, None, "a root session sends no namespace");
        assert!(calls.iter().all(|c| c.3 == "op-token"), "always as the operator");
    }
}
