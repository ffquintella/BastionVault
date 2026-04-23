//! Tauri commands orchestrating the OAuth consent flow for cloud
//! storage targets (OneDrive / Google Drive / Dropbox).
//!
//! Mirrors `bvault operator cloud-target connect` (CLI) but splits
//! the flow into two commands so the frontend can drive the browser
//! itself via the Tauri `shell` plugin between steps:
//!
//!   1. `cloud_target_start_connect` — binds the loopback listener,
//!      composes the authorization URL, stashes the session under an
//!      opaque session id, and returns `{session_id, consent_url}`.
//!      The frontend shells out to the system browser with that URL.
//!
//!   2. `cloud_target_complete_connect` — pulls the session back out
//!      by id, blocks (on a worker thread) waiting for the callback,
//!      exchanges the authorization code for tokens, and atomically
//!      persists the refresh token to the configured `credentials_ref`.
//!
//! The session state lives in `AppState::cloud_sessions` so a stray
//! Cancel-before-complete can't leak the bound loopback port — the
//! `cloud_target_cancel_connect` command drops the session entry
//! (and with it the listener) on the user's explicit cancel.

use bastion_vault::storage::physical::file::{creds, oauth};
use serde::Serialize;
use std::time::Duration;
use tauri::{State, async_runtime};

use crate::state::{AppState, CloudSession};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartConnectResult {
    pub session_id: String,
    pub consent_url: String,
}

/// Bind the loopback listener, compose the authorization URL, and
/// stash the session for `cloud_target_complete_connect` to pick up.
///
/// Validates `credentials_ref` at this step so typos surface before
/// the user is bounced to the consent page. `keychain:` refs are
/// rejected here with the same Phase-7-deferred message as the
/// reader — when the keychain writer lands, this check goes away.
#[tauri::command]
pub async fn cloud_target_start_connect(
    state: State<'_, AppState>,
    target: String,
    client_id: String,
    client_secret: Option<String>,
    credentials_ref: String,
) -> Result<StartConnectResult, String> {
    // Fail-fast on an unwritable `credentials_ref` so we don't burn
    // the user's time on a consent round-trip that can't finish.
    // `persist` with empty bytes would be a destructive test; instead
    // we inspect the scheme directly.
    validate_credentials_ref_writable(&credentials_ref)?;

    let provider = oauth::well_known_provider(&target).map_err(|e| e.to_string())?;
    let creds = oauth::OAuthCredentials {
        client_id: client_id.clone(),
        client_secret: client_secret.clone(),
    };
    // Loopback-only — the redirect URI must stay on the same machine
    // as the Tauri app. No point making this configurable.
    let session = oauth::begin_consent(&provider, &creds, "127.0.0.1")
        .map_err(|e| e.to_string())?;

    let consent_url = session.consent_url.to_string();
    // Generate a short session id. A UUID would be overkill here —
    // the session lives for at most 5 minutes and is validated on
    // lookup. 16 bytes base64url is plenty.
    let session_id = short_id();

    let entry = CloudSession {
        session,
        provider,
        creds,
        credentials_ref,
    };

    state
        .cloud_sessions
        .lock()
        .map_err(|e| format!("cloud session map poisoned: {e}"))?
        .insert(session_id.clone(), entry);

    Ok(StartConnectResult {
        session_id,
        consent_url,
    })
}

/// Block until the browser callback, exchange the authorization
/// code for tokens, and persist the refresh token. Blocks the
/// calling Tauri command for up to `timeout_secs` (default 300).
#[tauri::command]
pub async fn cloud_target_complete_connect(
    state: State<'_, AppState>,
    session_id: String,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(300));

    // Take the session out of the map — we're about to consume it
    // on the wait_for_callback side, and leaving a half-consumed
    // handle in the map would only cause confusion.
    let CloudSession {
        session,
        provider,
        creds,
        credentials_ref,
    } = state
        .cloud_sessions
        .lock()
        .map_err(|e| format!("cloud session map poisoned: {e}"))?
        .remove(&session_id)
        .ok_or_else(|| {
            "no such cloud-target session (it may have timed out or been cancelled)".to_string()
        })?;

    // Offload the whole blocking sequence (accept → parse → POST
    // token endpoint → persist file) to a worker so we don't park
    // the Tauri async runtime on the loopback accept loop.
    let redirect_uri = session.redirect_uri.clone();
    let verifier = session.verifier.clone();
    async_runtime::spawn_blocking(move || -> Result<(), String> {
        let callback = session.wait_for_callback(timeout).map_err(|e| e.to_string())?;
        let token_response =
            oauth::exchange_code(&provider, &creds, &callback.code, &verifier, &redirect_uri)
                .map_err(|e| e.to_string())?;
        let refresh_token = token_response
            .refresh_token
            .as_deref()
            .ok_or_else(|| {
                "provider returned no refresh_token — check that your app registration \
                 grants offline access (for Google Drive, the target_provider config \
                 already sets access_type=offline and prompt=consent)"
                    .to_string()
            })?;
        creds::persist(&credentials_ref, refresh_token.as_bytes()).map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|e| format!("worker task: {e}"))?
}

/// Drop a pending consent session without completing it. The
/// underlying TCP listener is released with the `CloudSession` on
/// removal from the map. Safe to call twice — missing session is
/// silently `Ok`.
#[tauri::command]
pub async fn cloud_target_cancel_connect(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    state
        .cloud_sessions
        .lock()
        .map_err(|e| format!("cloud session map poisoned: {e}"))?
        .remove(&session_id);
    Ok(())
}

/// Same URI grammar as the server-side `credentials_ref`, narrowed
/// to the schemes we can *write* (Phase-3b). `inline:` and `env:`
/// are read-only and rejected; `keychain:` is deferred to a later
/// phase and rejected with a specific message. `file:` is the only
/// writable scheme today.
fn validate_credentials_ref_writable(reference: &str) -> Result<(), String> {
    let trimmed = reference.trim();
    let (scheme, _) = trimmed.split_once(':').ok_or_else(|| {
        "credentials_ref must include a scheme (`file:`, `env:`, `inline:`, `keychain:`)"
            .to_string()
    })?;
    match scheme {
        "file" => Ok(()),
        "env" => Err(
            "`env:` credentials_ref cannot be written durably — use `file:` to persist the \
             refresh token"
                .into(),
        ),
        "inline" => Err(
            "`inline:` credentials_ref is read-only (the value would have to live in the \
             server config)"
                .into(),
        ),
        "keychain" => {
            // Don't pre-reject: the server may have been built with
            // `cloud_keychain`, in which case persistence works. If
            // it wasn't, `creds::persist` surfaces a clear error at
            // completion time pointing at the build feature.
            Ok(())
        }
        other => Err(format!(
            "unknown credentials_ref scheme `{other}` (expected `file` / `env` / `inline` / `keychain`)"
        )),
    }
}

/// Base64url-encoded 16 random bytes. Not crypto-sensitive — just an
/// opaque handle the frontend carries between the two commands —
/// but using PKCE's verifier helper keeps us from importing `rand`
/// directly in this file.
fn short_id() -> String {
    // `pkce_verifier` is a 72-byte URL-safe random string. 16 chars
    // is more than enough for our purposes; truncate to keep the
    // logs readable when we ever print a session id.
    let v = oauth::pkce_verifier();
    v.chars().take(22).collect()
}
