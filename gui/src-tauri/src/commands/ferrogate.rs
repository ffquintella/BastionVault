//! Tauri commands for the FerroGate machine-auth admin page. Each routes
//! through `make_request` to the `auth/ferrogate/*` endpoints. Mirrors the
//! AppRole command pattern.

use bv_client::Operation;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

/// Trust-anchor configuration for the ferrogate mount.
#[derive(Serialize, Deserialize, Default)]
pub struct FerroGateConfig {
    #[serde(default)]
    pub trust_domain: String,
    #[serde(default)]
    pub expected_audience: String,
    #[serde(default)]
    pub jwks_source: String,
    #[serde(default)]
    pub cmis_endpoint: String,
    #[serde(default)]
    pub cmis_srv: String,
    #[serde(default)]
    pub cmis_spki_pins: Vec<String>,
    #[serde(default)]
    pub static_jwks: String,
    #[serde(default)]
    pub accept_svid: bool,
    #[serde(default)]
    pub clock_leeway_secs: i64,
    #[serde(default)]
    pub default_token_ttl: u64,
    #[serde(default)]
    pub cmis_tls_enable: bool,
    #[serde(default)]
    pub cmis_same_host: bool,
    #[serde(default)]
    pub jwks_refresh_secs: i64,
    #[serde(default)]
    pub bootstrap_root_auto_approve: bool,
    #[serde(default)]
    pub bootstrap_policies: Vec<String>,
    #[serde(default)]
    pub require_user_token: bool,
    #[serde(default)]
    pub require_machine_identity: bool,
}

/// A machine enrolment summary as listed by the admin endpoint.
#[derive(Serialize, Deserialize, Default)]
pub struct FerroGateMachine {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub spiffe_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub ek_cert_sha384: String,
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub parent_svid: String,
    #[serde(default)]
    pub first_seen_at: i64,
    #[serde(default)]
    pub approved_at: i64,
    #[serde(default)]
    pub approver: String,
    #[serde(default)]
    pub last_login_at: i64,
    #[serde(default)]
    pub last_login_ip: String,
    #[serde(default)]
    pub reject_reason: String,
    #[serde(default)]
    pub comment: String,
}

/// The server's machine-identity requirement, as advertised by the
/// unauthenticated `auth/ferrogate/requirement` endpoint. This is the SERVER's
/// declaration — the client obeys it and cannot turn it off.
#[derive(Serialize, Deserialize, Default)]
pub struct FerroGateRequirement {
    /// When true, this server rejects any session that isn't FerroGate
    /// machine-bound; the connect flow must run the machine gate.
    #[serde(default)]
    pub require_machine_identity: bool,
    /// Audience the client should mint its child token for (the server's
    /// configured `expected_audience`); empty when unset.
    #[serde(default)]
    pub expected_audience: String,
    /// FerroGate trust domain the server expects; informational.
    #[serde(default)]
    pub trust_domain: String,
}

/// Ask the connected server whether it requires FerroGate machine identity.
/// Unauthenticated (the endpoint is in the mount's `unauth_paths`). A server
/// with no `ferrogate` mount — or any read failure — is treated as "not
/// required", so this never blocks connecting to a non-FerroGate server.
#[tauri::command]
pub async fn ferrogate_requirement(state: State<'_, AppState>) -> CmdResult<FerroGateRequirement> {
    match make_request(&state, Operation::Read, "auth/ferrogate/requirement".into(), None).await {
        Ok(resp) => match resp.and_then(|r| r.data) {
            Some(data) => Ok(serde_json::from_value(Value::Object(data)).unwrap_or_default()),
            None => Ok(FerroGateRequirement::default()),
        },
        // No ferrogate mount / route absent / transport hiccup ⇒ not required.
        Err(_) => Ok(FerroGateRequirement::default()),
    }
}

#[tauri::command]
pub async fn ferrogate_read_config(state: State<'_, AppState>) -> CmdResult<FerroGateConfig> {
    let resp = make_request(&state, Operation::Read, "auth/ferrogate/config".into(), None).await?;
    match resp.and_then(|r| r.data) {
        Some(data) => Ok(serde_json::from_value(Value::Object(data)).unwrap_or_default()),
        None => Ok(FerroGateConfig::default()),
    }
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn ferrogate_write_config(
    state: State<'_, AppState>,
    trust_domain: String,
    expected_audience: String,
    jwks_source: String,
    cmis_endpoint: String,
    cmis_srv: String,
    cmis_spki_pins: String,
    static_jwks: String,
    accept_svid: bool,
    cmis_tls_enable: bool,
    cmis_same_host: bool,
    bootstrap_root_auto_approve: bool,
    bootstrap_policies: String,
    require_user_token: bool,
    require_machine_identity: bool,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("trust_domain".into(), Value::String(trust_domain));
    body.insert("expected_audience".into(), Value::String(expected_audience));
    if !jwks_source.is_empty() {
        body.insert("jwks_source".into(), Value::String(jwks_source));
    }
    body.insert("cmis_endpoint".into(), Value::String(cmis_endpoint));
    body.insert("cmis_srv".into(), Value::String(cmis_srv));
    body.insert("cmis_spki_pins".into(), Value::String(cmis_spki_pins));
    body.insert("static_jwks".into(), Value::String(static_jwks));
    body.insert("accept_svid".into(), Value::Bool(accept_svid));
    body.insert("cmis_tls_enable".into(), Value::Bool(cmis_tls_enable));
    body.insert("cmis_same_host".into(), Value::Bool(cmis_same_host));
    body.insert("bootstrap_root_auto_approve".into(), Value::Bool(bootstrap_root_auto_approve));
    body.insert("bootstrap_policies".into(), Value::String(bootstrap_policies));
    body.insert("require_user_token".into(), Value::Bool(require_user_token));
    body.insert("require_machine_identity".into(), Value::Bool(require_machine_identity));

    make_request(&state, Operation::Write, "auth/ferrogate/config".into(), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ferrogate_list_machines(state: State<'_, AppState>) -> CmdResult<Vec<FerroGateMachine>> {
    let resp = make_request(&state, Operation::List, "auth/ferrogate/machines".into(), None).await?;
    let machines = resp
        .and_then(|r| r.data)
        .and_then(|d| d.get("machines").cloned())
        .and_then(|v| if let Value::Array(a) = v { Some(a) } else { None })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| serde_json::from_value(m).ok())
        .collect();
    Ok(machines)
}

#[tauri::command]
pub async fn ferrogate_approve(
    state: State<'_, AppState>,
    id: String,
    policies: String,
    ttl_seconds: i64,
    comment: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    if !policies.is_empty() {
        body.insert("policies".into(), Value::String(policies));
    }
    body.insert("ttl_seconds".into(), Value::Number(ttl_seconds.max(0).into()));
    if !comment.is_empty() {
        body.insert("comment".into(), Value::String(comment));
    }
    make_request(&state, Operation::Write, format!("auth/ferrogate/machines/{id}/approve"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ferrogate_reject(state: State<'_, AppState>, id: String, reason: String) -> CmdResult<()> {
    let mut body = Map::new();
    if !reason.is_empty() {
        body.insert("reason".into(), Value::String(reason));
    }
    make_request(&state, Operation::Write, format!("auth/ferrogate/machines/{id}/reject"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ferrogate_revoke(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    make_request(&state, Operation::Write, format!("auth/ferrogate/machines/{id}/revoke"), None).await?;
    Ok(())
}

#[tauri::command]
pub async fn ferrogate_delete_machine(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("auth/ferrogate/machines/{id}"), None).await?;
    Ok(())
}

// ── Machine-identity client (MIA self-bootstrap) ───────────────────────────
//
// The commands above drive the *relying-party* side: they administer the
// `auth/ferrogate/*` endpoints that VERIFY a token someone presents. The
// commands below put the GUI on the *client* side of the same protocol —
// they dial the local FerroGate Machine Identity Agent (MIA) over its Unix
// helper socket, mint a short-lived DPoP-bound child token, and exchange it
// at `auth/<mount>/login` to self-enrol this host.
//
// The MIA wire format, DPoP proof construction, and JWK thumbprint are reused
// verbatim from the CLI (`bastion_vault::cli::command::ferrogate_mia`) so they
// stay byte-identical to what the server's `ferro-child-verify` verifies —
// there is no second copy of the crypto to drift.

/// Outcome of a machine self-login / self-enrolment attempt.
#[derive(Serialize, Default)]
pub struct FerroGateLoginResult {
    /// SPIFFE id read locally (unverified) from the minted child token —
    /// lets the UI show "who am I" even when the server denies enrolment.
    pub spiffe_id: String,
    /// True when the server minted a vault token (machine is approved).
    pub authenticated: bool,
    /// Classified enrolment outcome, so the UI can branch without parsing
    /// free-text error strings:
    /// - `approved` — token issued (`authenticated == true`)
    /// - `pending`  — known/first-seen but awaiting operator approval
    /// - `rejected` — operator explicitly denied this machine
    /// - `revoked`  — previously approved, now revoked
    ///
    /// Transport / verification / config failures are NOT represented here —
    /// they surface as a command `Err` so the UI shows them as hard errors.
    pub enrolment: String,
    /// Human-readable server reason for a non-approved outcome (empty when
    /// `authenticated`). Mirrors the server's `error_response` text.
    pub message: String,
    /// The issued vault token, when `authenticated`. The GUI displays it for
    /// copy-out; it deliberately does NOT replace the operator's admin
    /// session token, so exercising this tab cannot log the admin out.
    pub client_token: String,
    /// Policies attached to the issued token.
    pub policies: Vec<String>,
    /// Token lease lifetime in seconds, when known.
    pub lease_duration: u64,
}

/// Map a `ferrogate` login `error_response` text to a stable enrolment status,
/// or `None` when the failure is not an enrolment-gate decision (e.g. rate
/// limiting, token verification, JWKS resolution) and should surface as a hard
/// error instead. Keep these prefixes in sync with the server's `login`
/// handler in `src/modules/credential/ferrogate/path_machines.rs`.
#[cfg(unix)]
fn classify_enrolment_error(text: &str) -> Option<&'static str> {
    if text.starts_with("enrolment_pending") {
        Some("pending")
    } else if text.starts_with("enrolment_rejected") {
        Some("rejected")
    } else if text.starts_with("machine_revoked") {
        Some("revoked")
    } else {
        None
    }
}

/// Mint a child token from the MIA and build its DPoP proof. Runs the blocking
/// `std` socket I/O on a blocking thread so it never stalls the async runtime.
/// Returns `(child_token_jws, dpop_proof_jws, spiffe_id)`.
#[cfg(unix)]
async fn mia_mint(socket: String, audience: String, ttl: u32) -> Result<(String, String, String), String> {
    use bastion_vault::cli::command::ferrogate_mia::{self, DpopKey};
    tokio::task::spawn_blocking(move || {
        let dpop = DpopKey::generate();
        let child = ferrogate_mia::request_child_token(&socket, &audience, &dpop.jkt(), ttl)?;
        let proof = dpop.proof("POST", &audience);
        let spiffe = ferrogate_mia::jws_claim_str(&child.jws, "iss").unwrap_or_default();
        Ok((child.jws, proof, spiffe))
    })
    .await
    .map_err(|e| format!("MIA worker thread failed: {e}"))?
}

/// The MIA helper socket path for this host — resolved by inspecting the
/// installed MIA's own configuration (env override, then `mia.toml` /
/// `mia-<env>.toml`, then the per-OS wizard default), so the GUI prefills
/// wherever MIA actually listens rather than a hard-coded path that breaks when
/// the operator moves it. `environment` selects which config file the MIA wrote
/// (blank/None ⇒ the default `mia.toml`).
#[tauri::command]
pub fn ferrogate_default_socket(environment: Option<String>) -> String {
    #[cfg(unix)]
    {
        let env = environment.as_deref().map(str::trim).filter(|s| !s.is_empty());
        bastion_vault::cli::command::ferrogate_mia::resolve_mia_socket_for(env)
    }
    #[cfg(not(unix))]
    {
        let _ = environment;
        String::new()
    }
}

/// The MIA environment selectors installed on this host (the `<env>` of each
/// discovered `mia-<env>.toml`), so the GUI can offer them as autocomplete
/// suggestions. The default environment (`mia.toml`) is implicit — selected by
/// leaving the field blank — and is not listed.
#[cfg(unix)]
#[tauri::command]
pub fn ferrogate_list_environments() -> Vec<String> {
    bastion_vault::cli::command::ferrogate_mia::list_environments()
}

#[cfg(not(unix))]
#[tauri::command]
pub fn ferrogate_list_environments() -> Vec<String> {
    Vec::new()
}

/// Derive a complete `ferrogate` mount config from the FerroGate MIA installed
/// on this host: CMIS endpoint + SPKI pin from `mia.toml`, trust domain from
/// the signed allowlist, and the live composite JWKS fetched from CMIS. The GUI
/// uses this to prefill the config form ("Autofill from local MIA") so the
/// operator does not hand-copy any of it. This only *reads* local state and
/// fetches the (public) JWKS — it does not write the mount config; the form's
/// Save button does that.
#[cfg(unix)]
#[tauri::command]
pub async fn ferrogate_autoconfig(
    audience: String,
    environment: Option<String>,
) -> CmdResult<bastion_vault::cli::command::ferrogate_mia::FerrogateAutoConfig> {
    use bastion_vault::cli::command::ferrogate_mia;
    let audience = audience.trim().to_string();
    let env = environment.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(e) = env {
        ferrogate_mia::validate_environment(e).map_err(crate::error::CommandError::from)?;
    }
    ferrogate_mia::build_autoconfig(audience, env).await.map_err(Into::into)
}

#[cfg(not(unix))]
#[tauri::command]
pub async fn ferrogate_autoconfig(_audience: String, _environment: Option<String>) -> CmdResult<Value> {
    Err("FerroGate autoconfig is only available on Unix (the MIA is not supported on this platform yet)".into())
}

fn norm_socket(socket: String) -> String {
    let s = socket.trim();
    if s.is_empty() {
        ferrogate_default_socket(None)
    } else {
        s.to_string()
    }
}

fn norm_mount(mount: String) -> String {
    let m = mount.trim().trim_matches('/');
    if m.is_empty() { "ferrogate".to_string() } else { m.to_string() }
}

/// Dial the MIA, mint a child token, and exchange it at `auth/<mount>/login`.
/// On success the server returns a vault token (machine approved); a pending
/// or denied enrolment surfaces as an error carrying the server's reason.
#[cfg(unix)]
#[tauri::command]
pub async fn ferrogate_machine_login(
    state: State<'_, AppState>,
    audience: String,
    socket: String,
    mount: String,
    ttl: u32,
    user_token: Option<String>,
) -> CmdResult<FerroGateLoginResult> {
    let socket = norm_socket(socket);
    let mount = norm_mount(mount);
    let ttl = if ttl == 0 { 300 } else { ttl };

    let (jws, proof, spiffe) = mia_mint(socket, audience, ttl).await?;

    let mut body = Map::new();
    body.insert("token".into(), Value::String(jws));
    body.insert("dpop".into(), Value::String(proof));
    // Combined machine+user binding: when the caller hands us an already-
    // authenticated user token, the server intersects its policies with the
    // machine's and revokes the user token, returning the combined session.
    if let Some(ut) = user_token.filter(|t| !t.trim().is_empty()) {
        body.insert("user_token".into(), Value::String(ut));
    }

    let resp = super::dispatch_with_token(
        &state,
        Operation::Write,
        format!("auth/{mount}/login"),
        Some(body),
        "",
    )
    .await?;

    let auth = resp.as_ref().and_then(|r| r.auth.as_ref());
    let client_token = auth
        .and_then(|a| a.get("client_token"))
        .and_then(|t| t.as_str())
        .unwrap_or_default()
        .to_string();

    // No token minted: the server either denied enrolment (a gate decision we
    // classify and hand back as a typed result) or failed for a harder reason
    // (rate limit, bad token, JWKS) which we propagate as a command error.
    if client_token.is_empty() {
        let reason = resp
            .as_ref()
            .and_then(|r| r.data.as_ref())
            .and_then(|d| d.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("login did not return a token")
            .to_string();
        match classify_enrolment_error(&reason) {
            Some(status) => {
                return Ok(FerroGateLoginResult {
                    spiffe_id: spiffe,
                    authenticated: false,
                    enrolment: status.to_string(),
                    message: reason,
                    ..Default::default()
                });
            }
            None => return Err(reason.into()),
        }
    }

    let policies = auth
        .and_then(|a| a.get("policies"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let lease_duration = auth
        .and_then(|a| a.get("lease_duration"))
        .and_then(|v| v.as_u64())
        .or_else(|| resp.as_ref().and_then(|r| r.lease_duration))
        .unwrap_or(0);

    Ok(FerroGateLoginResult {
        spiffe_id: spiffe,
        authenticated: true,
        enrolment: "approved".to_string(),
        message: String::new(),
        client_token,
        policies,
        lease_duration,
    })
}

/// Report this machine's enrolment status without minting a vault token.
/// Returns the server's `data` payload (e.g. `{ status, policies, ... }`).
#[cfg(unix)]
#[tauri::command]
pub async fn ferrogate_machine_status(
    state: State<'_, AppState>,
    audience: String,
    socket: String,
    mount: String,
    ttl: u32,
) -> CmdResult<Value> {
    let socket = norm_socket(socket);
    let mount = norm_mount(mount);
    let ttl = if ttl == 0 { 300 } else { ttl };

    let (jws, proof, _spiffe) = mia_mint(socket, audience, ttl).await?;

    let mut body = Map::new();
    body.insert("token".into(), Value::String(jws));
    body.insert("dpop".into(), Value::String(proof));

    let resp = super::dispatch_with_token(
        &state,
        Operation::Write,
        format!("auth/{mount}/status"),
        Some(body),
        "",
    )
    .await?;

    Ok(resp.and_then(|r| r.data).map(Value::Object).unwrap_or(Value::Null))
}

/// Print this host's SPIFFE id, read locally from a freshly minted token.
/// No server round-trip — useful to confirm the MIA is reachable and which
/// identity it would present before attempting a login.
#[cfg(unix)]
#[tauri::command]
pub async fn ferrogate_whoami(socket: String) -> CmdResult<String> {
    let socket = norm_socket(socket);
    let (_jws, _proof, spiffe) = mia_mint(socket, "urn:bvault:ferrogate:whoami".into(), 60).await?;
    if spiffe.is_empty() {
        return Err("could not read SPIFFE id from the minted token".into());
    }
    Ok(spiffe)
}

// On non-Unix targets the MIA helper socket does not exist (Windows named-pipe
// support is deferred). Provide stubs so the Tauri command table is identical
// across platforms and the GUI gets a clear error instead of a missing command.
#[cfg(not(unix))]
#[tauri::command]
pub async fn ferrogate_machine_login(
    _state: State<'_, AppState>,
    _audience: String,
    _socket: String,
    _mount: String,
    _ttl: u32,
    _user_token: Option<String>,
) -> CmdResult<FerroGateLoginResult> {
    Err("FerroGate MIA login is only available on Unix (the MIA helper socket is not supported on this platform yet)".into())
}

#[cfg(not(unix))]
#[tauri::command]
pub async fn ferrogate_machine_status(
    _state: State<'_, AppState>,
    _audience: String,
    _socket: String,
    _mount: String,
    _ttl: u32,
) -> CmdResult<Value> {
    Err("FerroGate MIA status is only available on Unix".into())
}

#[cfg(not(unix))]
#[tauri::command]
pub async fn ferrogate_whoami(_socket: String) -> CmdResult<String> {
    Err("FerroGate MIA whoami is only available on Unix".into())
}
