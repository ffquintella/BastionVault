//! Connect-time MFA re-validation, host side
//! (`features/connect-mfa-and-fido2-ssh.md`).
//!
//! Drives the two-step ceremony the resource backend exposes:
//!
//!   1. `connect_mfa_begin` asks the server whether the profile is gated and
//!      which factors the operator can satisfy it with. The server decides —
//!      the host never inspects the profile's `require_mfa` flag itself, so a
//!      tampered local copy of the resource record changes nothing.
//!   2. `connect_mfa_verify_totp` / `connect_mfa_verify_fido2` prove one
//!      factor and return the single-use connect ticket.
//!
//! The ticket then rides along on the session open: the brokered path sends it
//! to `rustion/v2/session/open`, and the direct path redeems it at
//! `resources/v2/connect/authorize`.

use serde::Serialize;
use serde_json::{Map, Value};
use tauri::{AppHandle, State};

use bv_client::Operation;

use crate::commands::make_request;
use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

pub const RESOURCE_MOUNT: &str = "resources/";

/// What the server says about a profile's gate, plus the FIDO2 challenge when
/// the operator has a security key.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectMfaChallenge {
    /// Whether this profile requires re-validation at all. `false` ⇒ the
    /// caller proceeds straight to the session open with no ticket.
    pub required: bool,
    /// Factors the *calling operator* can actually use, server-ordered
    /// (FIDO2 first when available).
    pub methods: Vec<String>,
    /// WebAuthn `publicKey` request options, present only when `fido2` is in
    /// `methods`. Opaque to the frontend — it is handed straight back to
    /// `connect_mfa_verify_fido2`.
    pub fido2: Option<Value>,
}

/// A redeemed factor, ready to spend on one session open.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectMfaTicket {
    pub connect_ticket: String,
    pub expires_at: String,
    pub method: String,
}

fn begin_path() -> String {
    format!("{RESOURCE_MOUNT}v2/connect/mfa/begin")
}

fn verify_path() -> String {
    format!("{RESOURCE_MOUNT}v2/connect/mfa/verify")
}

fn target_body(resource: &str, profile_id: &str) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("resource".into(), Value::String(resource.to_string()));
    body.insert("profile_id".into(), Value::String(profile_id.to_string()));
    body
}

/// Ask the server whether this profile is gated, and start the ceremony if so.
#[tauri::command]
pub async fn connect_mfa_begin(
    state: State<'_, AppState>,
    resource_name: String,
    profile_id: String,
) -> CmdResult<ConnectMfaChallenge> {
    begin(&state, &resource_name, &profile_id).await
}

/// Non-command form so the connect path can run the same check inline.
pub async fn begin(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile_id: &str,
) -> CmdResult<ConnectMfaChallenge> {
    let body = target_body(resource_name, profile_id);
    let resp = make_request(state, Operation::Write, begin_path(), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();

    Ok(ConnectMfaChallenge {
        required: data.get("required").and_then(|v| v.as_bool()).unwrap_or(false),
        methods: data
            .get("methods")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|m| m.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        fido2: data.get("fido2").cloned(),
    })
}

/// Prove a TOTP code and collect the ticket.
#[tauri::command]
pub async fn connect_mfa_verify_totp(
    state: State<'_, AppState>,
    resource_name: String,
    profile_id: String,
    code: String,
) -> CmdResult<ConnectMfaTicket> {
    let code = code.trim().to_string();
    if code.is_empty() {
        return Err(CommandError::from("enter the current code from your authenticator app".to_string()));
    }
    let mut body = target_body(&resource_name, &profile_id);
    body.insert("method".into(), Value::String("totp".into()));
    body.insert("totp_code".into(), Value::String(code));
    finish(&state, body).await
}

/// Prove possession of the operator's registered passkey and collect the
/// ticket.
///
/// This is the *vault's* WebAuthn relying party — the same passkey used for
/// FIDO2 login, not the `sk-` SSH credential. A profile that both requires
/// MFA and uses the `fido2` credential source therefore asks for the key
/// twice: once to satisfy BastionVault, once to satisfy the SSH target. They
/// are different credentials proving different things.
#[tauri::command]
pub async fn connect_mfa_verify_fido2(
    state: State<'_, AppState>,
    app_handle: AppHandle,
    resource_name: String,
    profile_id: String,
    challenge: Value,
) -> CmdResult<ConnectMfaTicket> {
    let credential_json =
        crate::commands::fido2_native::assert_webauthn(&state, &app_handle, &challenge).await?;

    let mut body = target_body(&resource_name, &profile_id);
    body.insert("method".into(), Value::String("fido2".into()));
    body.insert("credential".into(), Value::String(credential_json));
    finish(&state, body).await
}

async fn finish(state: &State<'_, AppState>, body: Map<String, Value>) -> CmdResult<ConnectMfaTicket> {
    let resp = make_request(state, Operation::Write, verify_path(), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();

    let ticket = data.get("connect_ticket").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if ticket.is_empty() {
        // A verify that returns no ticket is a server-side contract break, not
        // a soft failure — refuse rather than continue ticketless into a
        // session open that will be denied with a less useful message.
        return Err(CommandError::from(
            "MFA verification returned no connect ticket; the session was not opened".to_string(),
        ));
    }
    Ok(ConnectMfaTicket {
        connect_ticket: ticket,
        expires_at: data.get("expires_at").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        method: data.get("method").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
    })
}

/// Redeem the ticket on the direct path.
///
/// Called by `session_open_ssh` / `session_open_rdp` before any session window
/// opens. On an ungated profile the server answers `authorized` with no ticket
/// required, so this is a cheap no-op rather than a branch the host has to
/// decide for itself.
pub async fn authorize_direct(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile_id: &str,
    connect_ticket: Option<&str>,
) -> CmdResult<()> {
    let mut body = target_body(resource_name, profile_id);
    if let Some(t) = connect_ticket.map(str::trim).filter(|t| !t.is_empty()) {
        body.insert("connect_ticket".into(), Value::String(t.to_string()));
    }
    let path = format!("{RESOURCE_MOUNT}v2/connect/authorize");
    let resp = make_request(state, Operation::Write, path, Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    if !data.get("authorized").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Err(CommandError::from(
            "the server did not authorize this connection".to_string(),
        ));
    }
    Ok(())
}
