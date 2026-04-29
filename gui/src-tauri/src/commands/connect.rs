//! Tauri commands for the Resource Connect SSH/RDP session windows.
//!
//! Phase 3 ships SSH with the **Secret** credential source.
//! The credential resolver runs entirely on the Rust side: the
//! frontend supplies (resource_name, secret_id, profile_id); the
//! command pulls the secret out of barrier-encrypted storage,
//! resolves the credential into [`session::ssh::SshCredential`],
//! and feeds it straight to russh. The credential bytes never
//! cross the IPC boundary back to the JS layer.

use std::collections::HashMap;

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder};
use zeroize::Zeroizing;

use crate::error::{CmdResult, CommandError};
use crate::session::{
    self,
    ssh::{open_ssh_session, SshCredential, SshOpenArgs, SshOpenOutcome, CONNECT_TIMEOUT},
    SshControl,
};
use crate::state::AppState;

const RESOURCE_MOUNT: &str = "v2/resources/";

#[derive(Deserialize)]
pub struct SshOpenRequest {
    /// Resource name the profile lives on. Used to load the
    /// metadata + the secret.
    pub resource_name: String,
    /// Profile id — resolves protocol/target/user/credential
    /// source. The host re-reads the profile from the resource
    /// rather than trusting any client-side copy of it.
    pub profile_id: String,
}

#[derive(Serialize)]
pub struct SshOpenResponse {
    pub token: String,
    pub stdout_event: String,
    pub closed_event: String,
    pub window_label: String,
}

#[tauri::command]
pub async fn session_open_ssh(
    state: State<'_, AppState>,
    app: AppHandle,
    request: SshOpenRequest,
) -> CmdResult<SshOpenResponse> {
    // Load the resource metadata.
    let meta = read_resource_meta(&state, &request.resource_name).await?;

    // Resolve the profile.
    let profile = find_profile(&meta, &request.profile_id)
        .ok_or_else(|| CommandError::from(format!(
            "profile `{}` not found on resource `{}`",
            request.profile_id, request.resource_name
        )))?;

    // Compute the effective target, user, port from the profile +
    // resource metadata defaults.
    let host = profile_host(&profile, &meta).ok_or_else(|| {
        CommandError::from("resource has no hostname or ip_address; set one or override target_host on the profile".to_string())
    })?;
    let port = profile_port(&profile);
    let username = profile_username(&profile);
    if username.is_empty() {
        return Err(CommandError::from(
            "profile.username is required for SSH (no operator default)".to_string(),
        ));
    }
    let host_key_fingerprint = profile
        .get("host_key_pin")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let label = format!("ssh {username}@{host}:{port}");

    // Resolve the credential source. Phase 3 = Secret only.
    let credential = resolve_secret_credential(&state, &request.resource_name, &profile).await?;

    // Run the connect with a hard timeout so a wedged DNS/TCP/TLS
    // doesn't lock the calling Tauri command.
    let outcome: SshOpenOutcome = tokio::time::timeout(
        CONNECT_TIMEOUT,
        open_ssh_session(
            app.clone(),
            &state,
            SshOpenArgs {
                host,
                port,
                username: username.clone(),
                credential,
                host_key_fingerprint,
                label: label.clone(),
            },
        ),
    )
    .await
    .map_err(|_| CommandError::from(format!(
        "ssh: connect+auth timed out after {}s", CONNECT_TIMEOUT.as_secs()
    )))?
    .map_err(|e| CommandError::from(e))?;

    // Spawn the SessionSshWindow into a new WebviewWindow. The
    // window's React route claims the session via the token + the
    // event channel names returned in `outcome`.
    let window_label = format!("ssh-{}", outcome.token);
    // We use HashRouter on the frontend, so the route fragment
    // sits inside the URL hash. Tauri's WebviewUrl::App takes a
    // path relative to the app's index — `index.html#/path` gets
    // the React router to match `/path`.
    let url = format!(
        "index.html#/session/ssh?token={}&stdout={}&closed={}&label={}",
        urlencoding::encode(&outcome.token),
        urlencoding::encode(&outcome.stdout_event),
        urlencoding::encode(&outcome.closed_event),
        urlencoding::encode(&label),
    );
    let win = WebviewWindowBuilder::new(&app, &window_label, WebviewUrl::App(url.into()))
        .title(format!("BastionVault — {label}"))
        .inner_size(900.0, 540.0)
        .resizable(true)
        .build()
        .map_err(|e| CommandError::from(format!("spawn window: {e}")))?;
    // Hook the close button so the operator x'ing the window
    // tears down the SSH session as a side-effect.
    let token_for_close = outcome.token.clone();
    let app_for_close = app.clone();
    win.on_window_event(move |ev| {
        if let tauri::WindowEvent::CloseRequested { .. } = ev {
            let token = token_for_close.clone();
            let app = app_for_close.clone();
            tauri::async_runtime::spawn(async move {
                let s = app.state::<AppState>();
                let _ = session::ssh::send_control(&s, &token, SshControl::Close).await;
                session::ssh::drop_session(&s, &token).await;
                log::info!("resource-connect/ssh: window-close → session drop {token}");
            });
        }
    });

    log::info!(
        "resource-connect/ssh: spawned window {window_label} for {label}"
    );

    Ok(SshOpenResponse {
        token: outcome.token,
        stdout_event: outcome.stdout_event,
        closed_event: outcome.closed_event,
        window_label,
    })
}

#[derive(Deserialize)]
pub struct SshInputRequest {
    pub token: String,
    /// Base64-encoded keystroke bytes.
    pub bytes_b64: String,
}

#[tauri::command]
pub async fn session_input(
    state: State<'_, AppState>,
    request: SshInputRequest,
) -> CmdResult<()> {
    let bytes = session::ssh::decode_b64(&request.bytes_b64)
        .map_err(CommandError::from)?;
    session::ssh::send_control(&state, &request.token, SshControl::Data(bytes))
        .await
        .map_err(CommandError::from)
}

#[derive(Deserialize)]
pub struct SshResizeRequest {
    pub token: String,
    pub cols: u16,
    pub rows: u16,
}

#[tauri::command]
pub async fn session_resize(
    state: State<'_, AppState>,
    request: SshResizeRequest,
) -> CmdResult<()> {
    session::ssh::send_control(
        &state,
        &request.token,
        SshControl::Resize {
            cols: request.cols,
            rows: request.rows,
        },
    )
    .await
    .map_err(CommandError::from)
}

#[derive(Deserialize)]
pub struct RdpOpenRequest {
    pub resource_name: String,
    pub profile_id: String,
}

#[derive(Serialize)]
pub struct RdpOpenResponse {
    pub token: String,
    pub frame_event: String,
    pub closed_event: String,
    pub window_label: String,
    pub width: u16,
    pub height: u16,
}

/// Open an RDP session window. Phase 4 ships the surface; the
/// transport itself is stubbed pending an `ironrdp` upstream that
/// stops pinning `=crypto-common 0.2.0-rc.4` against our existing
/// `digest 0.11` stack. The window opens regardless so an operator
/// can see exactly what's in flight; the body shows the dep-blocker
/// banner with a link to the spec.
#[tauri::command]
pub async fn session_open_rdp(
    state: State<'_, AppState>,
    app: AppHandle,
    request: RdpOpenRequest,
) -> CmdResult<RdpOpenResponse> {
    let meta = read_resource_meta(&state, &request.resource_name).await?;
    let profile = find_profile(&meta, &request.profile_id).ok_or_else(|| {
        CommandError::from(format!(
            "profile `{}` not found on resource `{}`",
            request.profile_id, request.resource_name
        ))
    })?;
    let host = profile_host(&profile, &meta).ok_or_else(|| {
        CommandError::from(
            "resource has no hostname or ip_address; set one or override target_host on the profile"
                .to_string(),
        )
    })?;
    let port = profile
        .get("target_port")
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(3389);
    let username = profile_username(&profile);
    if username.is_empty() {
        return Err(CommandError::from(
            "profile.username is required for RDP".to_string(),
        ));
    }
    let label = format!("rdp {username}@{host}:{port}");

    let password = resolve_secret_credential_for_rdp(&state, &request.resource_name, &profile).await?;

    // Open the real RDP transport.
    let outcome = session::rdp::open_rdp_session(
        app.clone(),
        &state,
        session::rdp::RdpOpenArgs {
            host,
            port,
            username,
            password,
            domain: None,
            label: label.clone(),
        },
    )
    .await
    .map_err(CommandError::from)?;

    let window_label = format!("rdp-{}", outcome.token);
    let url = format!(
        "index.html#/session/rdp?token={}&frame={}&closed={}&label={}&w={}&h={}",
        urlencoding::encode(&outcome.token),
        urlencoding::encode(&outcome.frame_event),
        urlencoding::encode(&outcome.closed_event),
        urlencoding::encode(&label),
        outcome.width,
        outcome.height,
    );
    let win = WebviewWindowBuilder::new(&app, &window_label, WebviewUrl::App(url.into()))
        .title(format!("BastionVault — {label}"))
        .inner_size((outcome.width as f64) + 8.0, (outcome.height as f64) + 50.0)
        .resizable(true)
        .build()
        .map_err(|e| CommandError::from(format!("spawn window: {e}")))?;
    let token_for_close = outcome.token.clone();
    let app_for_close = app.clone();
    win.on_window_event(move |ev| {
        if let tauri::WindowEvent::CloseRequested { .. } = ev {
            let token = token_for_close.clone();
            let app = app_for_close.clone();
            tauri::async_runtime::spawn(async move {
                let s = app.state::<AppState>();
                let _ = session::rdp::send_control(&s, &token, session::rdp::RdpControl::Close).await;
                session::rdp::drop_session(&s, &token).await;
            });
        }
    });

    Ok(RdpOpenResponse {
        token: outcome.token,
        frame_event: outcome.frame_event,
        closed_event: outcome.closed_event,
        window_label,
        width: outcome.width,
        height: outcome.height,
    })
}

#[derive(Deserialize)]
pub struct RdpInputMouseRequest {
    pub token: String,
    pub x: u16,
    pub y: u16,
    /// Empty for moves; "down" / "up" for clicks.
    pub button: Option<String>,
    pub button_index: Option<u8>,
}

#[tauri::command]
pub async fn session_input_rdp_mouse(
    state: State<'_, AppState>,
    request: RdpInputMouseRequest,
) -> CmdResult<()> {
    let ctl = match (request.button.as_deref(), request.button_index) {
        (Some("down"), Some(idx)) => session::rdp::RdpControl::PointerButton {
            button_index: idx,
            pressed: true,
            x: request.x,
            y: request.y,
        },
        (Some("up"), Some(idx)) => session::rdp::RdpControl::PointerButton {
            button_index: idx,
            pressed: false,
            x: request.x,
            y: request.y,
        },
        _ => session::rdp::RdpControl::PointerMove {
            x: request.x,
            y: request.y,
        },
    };
    session::rdp::send_control(&state, &request.token, ctl)
        .await
        .map_err(CommandError::from)
}

#[derive(Deserialize)]
pub struct RdpInputKeyRequest {
    pub token: String,
    pub js_code: String,
    pub pressed: bool,
}

#[tauri::command]
pub async fn session_input_rdp_key(
    state: State<'_, AppState>,
    request: RdpInputKeyRequest,
) -> CmdResult<()> {
    session::rdp::send_control(
        &state,
        &request.token,
        session::rdp::RdpControl::Key {
            js_code: request.js_code,
            pressed: request.pressed,
        },
    )
    .await
    .map_err(CommandError::from)
}

async fn resolve_secret_credential_for_rdp(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile: &Value,
) -> Result<zeroize::Zeroizing<String>, CommandError> {
    let cs = profile.get("credential_source").ok_or_else(|| {
        CommandError::from("profile is missing credential_source".to_string())
    })?;
    let kind = cs.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if kind != "secret" {
        return Err(CommandError::from(format!(
            "credential source `{kind}` is not implemented yet — Phase 4 supports `secret` only"
        )));
    }
    let secret_id = cs
        .get("secret_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::from("credential_source.secret_id is required"))?;
    let path = format!("{RESOURCE_MOUNT}secrets/{resource_name}/{secret_id}");
    let resp = make_request(state, Operation::Read, path, None).await?;
    let data: HashMap<String, Value> = resp
        .and_then(|r| r.data)
        .map(|m| m.into_iter().collect())
        .unwrap_or_default();
    let password = data
        .get("password")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default();
    if password.is_empty() {
        return Err(CommandError::from(format!(
            "secret `{secret_id}` carries no `password` field — RDP CredSSP requires a password"
        )));
    }
    Ok(zeroize::Zeroizing::new(password))
}

#[derive(Deserialize)]
pub struct SshCloseRequest {
    pub token: String,
}

#[tauri::command]
pub async fn session_close(
    state: State<'_, AppState>,
    request: SshCloseRequest,
) -> CmdResult<()> {
    // Best-effort fan-out: we don't know whether the token names
    // an SSH or RDP session, so try both. The mismatched one
    // returns an error we ignore. drop_session removes either kind.
    let _ = session::ssh::send_control(&state, &request.token, SshControl::Close).await;
    let _ = session::rdp::send_control(
        &state,
        &request.token,
        session::rdp::RdpControl::Close,
    )
    .await;
    session::ssh::drop_session(&state, &request.token).await;
    session::rdp::drop_session(&state, &request.token).await;
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────

async fn make_request(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> Result<Option<bastion_vault::logical::Response>, CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = operation;
    req.path = path;
    req.client_token = token;
    req.body = body;

    core.handle_request(&mut req).await.map_err(CommandError::from)
}

async fn read_resource_meta(
    state: &State<'_, AppState>,
    name: &str,
) -> Result<Map<String, Value>, CommandError> {
    let path = format!("{RESOURCE_MOUNT}{name}");
    let resp = make_request(state, Operation::Read, path, None).await?;
    Ok(resp.and_then(|r| r.data).unwrap_or_default())
}

fn find_profile(meta: &Map<String, Value>, profile_id: &str) -> Option<Value> {
    meta.get("connection_profiles")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|p| p.get("id").and_then(|i| i.as_str()) == Some(profile_id))
                .cloned()
        })
}

fn profile_host(profile: &Value, meta: &Map<String, Value>) -> Option<String> {
    profile
        .get("target_host")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| meta.get("hostname").and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
        .or_else(|| meta.get("ip_address").and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
        .map(|s| s.to_string())
}

fn profile_port(profile: &Value) -> u16 {
    profile
        .get("target_port")
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(22)
}

fn profile_username(profile: &Value) -> String {
    profile
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

async fn resolve_secret_credential(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile: &Value,
) -> Result<SshCredential, CommandError> {
    let cs = profile.get("credential_source").ok_or_else(|| {
        CommandError::from("profile is missing credential_source".to_string())
    })?;
    let kind = cs.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if kind != "secret" {
        return Err(CommandError::from(format!(
            "credential source `{kind}` is not implemented yet — Phase 3 supports `secret` only"
        )));
    }
    let secret_id = cs
        .get("secret_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::from("credential_source.secret_id is required"))?;
    let path = format!("{RESOURCE_MOUNT}secrets/{resource_name}/{secret_id}");
    let resp = make_request(state, Operation::Read, path, None).await?;
    let data: HashMap<String, Value> = resp
        .and_then(|r| r.data)
        .map(|m| m.into_iter().collect())
        .unwrap_or_default();

    let private_key = data
        .get("private_key")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default();
    let passphrase = data
        .get("passphrase")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default();
    let password = data
        .get("password")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default();

    if !private_key.is_empty() {
        Ok(SshCredential::PrivateKey {
            pem: Zeroizing::new(private_key),
            passphrase: if passphrase.is_empty() {
                None
            } else {
                Some(Zeroizing::new(passphrase))
            },
        })
    } else if !password.is_empty() {
        Ok(SshCredential::Password(Zeroizing::new(password)))
    } else {
        Err(CommandError::from(format!(
            "secret `{secret_id}` carries no `password` or `private_key` field — Connect can't authenticate"
        )))
    }
}
