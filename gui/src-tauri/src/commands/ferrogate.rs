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
    pub jwks_refresh_secs: i64,
    #[serde(default)]
    pub bootstrap_root_auto_approve: bool,
    #[serde(default)]
    pub bootstrap_policies: Vec<String>,
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
    cmis_spki_pins: String,
    static_jwks: String,
    accept_svid: bool,
    cmis_tls_enable: bool,
    bootstrap_root_auto_approve: bool,
    bootstrap_policies: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("trust_domain".into(), Value::String(trust_domain));
    body.insert("expected_audience".into(), Value::String(expected_audience));
    if !jwks_source.is_empty() {
        body.insert("jwks_source".into(), Value::String(jwks_source));
    }
    body.insert("cmis_endpoint".into(), Value::String(cmis_endpoint));
    body.insert("cmis_spki_pins".into(), Value::String(cmis_spki_pins));
    body.insert("static_jwks".into(), Value::String(static_jwks));
    body.insert("accept_svid".into(), Value::Bool(accept_svid));
    body.insert("cmis_tls_enable".into(), Value::Bool(cmis_tls_enable));
    body.insert("bootstrap_root_auto_approve".into(), Value::Bool(bootstrap_root_auto_approve));
    body.insert("bootstrap_policies".into(), Value::String(bootstrap_policies));

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
    /// The issued vault token, when `authenticated`. The GUI displays it for
    /// copy-out; it deliberately does NOT replace the operator's admin
    /// session token, so exercising this tab cannot log the admin out.
    pub client_token: String,
    /// Policies attached to the issued token.
    pub policies: Vec<String>,
    /// Token lease lifetime in seconds, when known.
    pub lease_duration: u64,
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
/// installed MIA's own configuration (env override, then `mia.toml`, then the
/// per-OS wizard default), so the GUI prefills wherever MIA actually listens
/// rather than a hard-coded path that breaks when the operator moves it.
#[tauri::command]
pub fn ferrogate_default_socket() -> String {
    #[cfg(unix)]
    {
        bastion_vault::cli::command::ferrogate_mia::resolve_mia_socket()
    }
    #[cfg(not(unix))]
    {
        String::new()
    }
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
) -> CmdResult<bastion_vault::cli::command::ferrogate_mia::FerrogateAutoConfig> {
    let audience = audience.trim().to_string();
    bastion_vault::cli::command::ferrogate_mia::build_autoconfig(audience)
        .await
        .map_err(Into::into)
}

#[cfg(not(unix))]
#[tauri::command]
pub async fn ferrogate_autoconfig(_audience: String) -> CmdResult<Value> {
    Err("FerroGate autoconfig is only available on Unix (the MIA is not supported on this platform yet)".into())
}

fn norm_socket(socket: String) -> String {
    let s = socket.trim();
    if s.is_empty() {
        ferrogate_default_socket()
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
) -> CmdResult<FerroGateLoginResult> {
    let socket = norm_socket(socket);
    let mount = norm_mount(mount);
    let ttl = if ttl == 0 { 300 } else { ttl };

    let (jws, proof, spiffe) = mia_mint(socket, audience, ttl).await?;

    let mut body = Map::new();
    body.insert("token".into(), Value::String(jws));
    body.insert("dpop".into(), Value::String(proof));

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

    if client_token.is_empty() {
        return Err("login did not return a token (machine not approved)".into());
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

    Ok(FerroGateLoginResult { spiffe_id: spiffe, authenticated: true, client_token, policies, lease_duration })
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
