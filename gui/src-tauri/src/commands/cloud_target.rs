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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tauri::{State, async_runtime};

use crate::preferences::{self, CloudStorageConfig};
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
    // Fixed port so the redirect URI stays stable across consent
    // flows — Dropbox (and Microsoft's non-PKCE mode) won't accept
    // a random ephemeral port. `get_oauth_redirect_uri` exposes the
    // matching URL so the user can register it at the provider's
    // dev console.
    let session = oauth::begin_consent(
        &provider,
        &creds,
        "127.0.0.1",
        Some(oauth::DEFAULT_LOOPBACK_PORT),
    )
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

// ── Cloud Vault bootstrap (Get Started screen) ─────────────────────
//
// These commands persist the user's choice of cloud-backed embedded
// vault. Called from the Get Started screen's "Cloud Vault" button
// before the usual init/open flow fires. Once saved,
// `embedded::build_backend` routes storage through the named cloud
// target on every subsequent boot.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudVaultConfigInput {
    /// Provider kind: `"s3"` / `"onedrive"` / `"gdrive"` / `"dropbox"`.
    pub target: String,
    /// Free-form target-specific config (bucket, region, client_id,
    /// credentials_ref, obfuscate_keys, etc.). Passed straight into
    /// the target's `from_config` constructor.
    pub config: HashMap<String, Value>,
}

/// Legacy-shape Cloud Vault set: upserts a Cloud entry in the new
/// vault list and flips `last_used_id` to it. Retained so older
/// frontend code (pre-multi-vault) keeps working; the redesigned
/// ConnectPage uses `vaults::add_vault_profile` + `set_last_used_vault`
/// directly for finer control over profile names.
#[tauri::command]
pub async fn set_cloud_vault_config(
    input: CloudVaultConfigInput,
) -> Result<(), String> {
    use preferences::{short_id, VaultProfile, VaultSpec};

    let mut prefs = preferences::load().map_err(|e| e.to_string())?;
    let config = CloudStorageConfig {
        target: input.target.clone(),
        config: input.config.into_iter().collect(),
    };

    // Upsert: find an existing Cloud entry targeting the same
    // provider (we have no better natural key without asking the
    // caller for one). Most operators have at most one cloud
    // vault per provider; multi-cloud-per-provider setups should
    // use the fine-grained `add_vault_profile` command with
    // distinct names.
    let existing_idx = prefs
        .vaults
        .iter()
        .position(|v| matches!(&v.spec, VaultSpec::Cloud { config: c } if c.target == input.target));
    let id = if let Some(idx) = existing_idx {
        prefs.vaults[idx].spec = VaultSpec::Cloud { config };
        prefs.vaults[idx].id.clone()
    } else {
        let id = short_id();
        prefs.vaults.push(VaultProfile {
            id: id.clone(),
            name: format!("Cloud Vault ({})", input.target),
            spec: VaultSpec::Cloud { config },
        });
        id
    };
    prefs.last_used_id = Some(id);
    preferences::save(&prefs).map_err(|e| e.to_string())?;
    Ok(())
}

/// Legacy-shape clear: drop the current default if it's a Cloud
/// entry. The vault stays in the saved list; only the "default"
/// pointer is reset.
#[tauri::command]
pub async fn clear_cloud_vault_config() -> Result<(), String> {
    let mut prefs = preferences::load().map_err(|e| e.to_string())?;
    let is_cloud_default = prefs
        .default_profile()
        .is_some_and(|p| matches!(p.spec, preferences::VaultSpec::Cloud { .. }));
    if is_cloud_default {
        prefs.last_used_id = None;
    }
    preferences::save(&prefs).map_err(|e| e.to_string())?;
    Ok(())
}

/// Legacy-shape read: returns the cloud config of the *current*
/// default vault if it's a Cloud entry, else `None`. New code
/// should enumerate via `list_vault_profiles` to see every saved
/// cloud vault.
#[tauri::command]
pub async fn get_cloud_vault_config() -> Result<Option<CloudStorageConfig>, String> {
    let prefs = preferences::load().map_err(|e| e.to_string())?;
    Ok(prefs
        .default_profile()
        .and_then(|p| match &p.spec {
            preferences::VaultSpec::Cloud { config } => Some(config.clone()),
            _ => None,
        }))
}

// ── Add-vault modal helpers ────────────────────────────────────────
//
// Two small conveniences that turn the Add Cloud Vault flow from
// "paste three strings" into "click Login + done":
//
//   * `suggest_credentials_ref_path` — returns the default file:
//     path the UI should prefill when the user picks a provider.
//     Keeps creds out of the process env / inline config and uses
//     the per-user config directory by default.
//
//   * `save_s3_credentials` — writes an access-key-id + secret
//     JSON blob to a fresh file under the same directory and
//     returns the resulting credentials_ref. S3 has no OAuth flow
//     to shortcut through, so this fills the "login" role for that
//     provider: enter the key pair once, we persist it at 0600 on
//     Unix, the UI moves on.

#[tauri::command]
pub async fn suggest_credentials_ref_path(target: String) -> Result<String, String> {
    let path = cloud_creds_dir()?.join(format!("{target}-refresh"));
    Ok(format!("file:{}", path.display()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct S3CredentialInput {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
}

#[tauri::command]
pub async fn save_s3_credentials(input: S3CredentialInput) -> Result<String, String> {
    if input.access_key_id.trim().is_empty() || input.secret_access_key.trim().is_empty() {
        return Err("access_key_id and secret_access_key are required".into());
    }
    // Timestamp-tagged filename so repeated Save calls don't
    // silently overwrite a working set of keys — the previous one
    // stays on disk until the user removes it.
    let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let path = cloud_creds_dir()?.join(format!("s3-{ts}.json"));
    let reference = format!("file:{}", path.display());

    let mut obj = serde_json::Map::new();
    obj.insert(
        "access_key_id".into(),
        Value::String(input.access_key_id.trim().to_string()),
    );
    obj.insert(
        "secret_access_key".into(),
        Value::String(input.secret_access_key.trim().to_string()),
    );
    if let Some(tok) = input
        .session_token
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        obj.insert("session_token".into(), Value::String(tok.to_string()));
    }
    let bytes = serde_json::to_vec_pretty(&Value::Object(obj))
        .map_err(|e| e.to_string())?;
    creds::persist(&reference, &bytes).map_err(|e| e.to_string())?;
    Ok(reference)
}

fn cloud_creds_dir() -> Result<std::path::PathBuf, String> {
    let base = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .ok_or("cannot determine per-user data dir")?;
    let dir = base.join(".bastion_vault_gui").join("cloud-creds");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    Ok(dir)
}

// ── Stable redirect URI + direct-token entry ───────────────────────
//
// For providers that require the OAuth redirect URI to *exactly*
// match what was pre-registered at the dev console (Dropbox is the
// strict case; Google / Microsoft are RFC-8252-compliant and accept
// any loopback port, but pre-registering a fixed port still simplifies
// the UX), we expose the canonical URI so the frontend can display
// it verbatim with a copy-to-clipboard button.
//
// The direct-token command is the shortcut for users whose provider
// lets them generate a long-lived access / refresh token at the
// console (Dropbox has a "Generate" button for this). Paste it in,
// we write it to the credentials_ref file, done — no redirect URI
// round-trip needed.

/// Return the exact loopback redirect URI the consent flow will
/// use. Displayed in the Add Cloud Vault modal so users know what
/// to register at the provider's dev console.
#[tauri::command]
pub async fn get_oauth_redirect_uri() -> Result<String, String> {
    Ok(format!(
        "http://127.0.0.1:{}/callback",
        oauth::DEFAULT_LOOPBACK_PORT
    ))
}

/// Persist a token the user generated directly at the provider's
/// dev console (e.g. Dropbox's "Generate" button). Same atomic
/// `creds::persist` path as the OAuth flow; returns the resulting
/// `credentials_ref` so the frontend can show it.
///
/// For Dropbox, the generated token is a long-lived access token.
/// `DropboxTarget` feeds it in as a "refresh token" — Dropbox's
/// refresh endpoint will reject it, but since the token doesn't
/// expire that's fine. (A proper short-lived-with-refresh setup
/// requires the full OAuth flow.) For OneDrive / Google Drive
/// this is strictly the refresh token; those providers don't
/// expose a "generate" button.
#[tauri::command]
pub async fn save_pasted_token(
    target: String,
    token: String,
) -> Result<String, String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err("token cannot be empty".into());
    }
    // Basic sanity check — reject obviously-wrong input like the
    // user accidentally pasting a whole URL or a JSON blob instead
    // of the raw token string.
    if trimmed.contains('\n') || trimmed.contains(' ') {
        return Err(
            "token contains whitespace — paste just the raw token string, not a URL \
             or JSON blob"
                .into(),
        );
    }
    // Wrap in a `{"access_token":"..."}` envelope so targets can
    // tell a long-lived access token (generated directly at the
    // provider's dev console, no refresh support) apart from a
    // plain-string refresh token the OAuth consent flow writes.
    // Dropbox's `ensure_access_token` recognises both shapes and
    // skips the `/oauth2/token` round-trip for the envelope case —
    // otherwise Dropbox returns
    // `{"error":"invalid_grant","error_description":"refresh token is malformed"}`.
    let path = cloud_creds_dir()?.join(format!("{target}-refresh"));
    let reference = format!("file:{}", path.display());
    let envelope = serde_json::json!({ "access_token": trimmed });
    let bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
    creds::persist(&reference, &bytes).map_err(|e| e.to_string())?;
    Ok(reference)
}
