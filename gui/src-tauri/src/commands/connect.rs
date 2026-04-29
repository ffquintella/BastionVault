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
    /// Optional operator-supplied credential payload. Required
    /// only for `LdapBindMode::Operator` profiles, where the
    /// frontend pops a prompt before calling open and forwards
    /// the typed username/password through this field.
    #[serde(default)]
    pub operator_credential: Option<OperatorCredential>,
}

#[derive(Deserialize, Default)]
pub struct OperatorCredential {
    pub username: String,
    pub password: String,
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
    // Allow empty here; LDAP sources can supply the username via
    // `effective_username`. We re-validate after resolution.
    let host_key_fingerprint = profile
        .get("host_key_pin")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Resolve the credential source. Phases 3 + 5 ship: Secret +
    // LDAP (operator-bind / static-role / library set).
    let resolved = resolve_ssh_credential(
        &state,
        &request.resource_name,
        &profile,
        request.operator_credential.as_ref(),
    )
    .await?;
    let credential = resolved.credential;
    // LDAP profiles can override the profile's username with the
    // one the cred resolver returned (static_role/library set
    // returns the canonical service-account username).
    let username = if let Some(u) = resolved.effective_username {
        u
    } else {
        username
    };
    if username.is_empty() {
        return Err(CommandError::from(
            "SSH profile has no username (set profile.username or use an LDAP credential source)"
                .to_string(),
        ));
    }
    let label = format!("ssh {username}@{host}:{port}");
    let on_close = resolved.on_close;

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
                on_close,
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
                let cleanup = session::ssh::drop_session(&s, &token).await;
                if let Some(c) = cleanup {
                    let s2 = app.state::<AppState>();
                    run_cleanup(&s2, c).await;
                }
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
    /// Same operator-bind credential channel as
    /// `SshOpenRequest::operator_credential`. Required for
    /// `LdapBindMode::Operator` profiles only.
    #[serde(default)]
    pub operator_credential: Option<OperatorCredential>,
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
    // For RDP we don't fail when the profile username is empty
    // — LDAP credential sources supply it. The check after
    // resolution catches the case where every source path is also
    // empty.

    let resolved = resolve_rdp_credential(
        &state,
        &request.resource_name,
        &profile,
        request.operator_credential.as_ref(),
    )
    .await?;
    let username = resolved.effective_username.unwrap_or(username);
    if username.is_empty() {
        return Err(CommandError::from(
            "RDP profile has no username (set profile.username, supply via the LDAP credential source, or use a Secret with a `username` field)"
                .to_string(),
        ));
    }
    let label = format!("rdp {username}@{host}:{port}");
    let on_close = resolved.on_close;

    // Open the real RDP transport.
    let outcome = session::rdp::open_rdp_session(
        app.clone(),
        &state,
        session::rdp::RdpOpenArgs {
            host,
            port,
            username,
            password: resolved.password,
            domain: resolved.domain,
            label: label.clone(),
            on_close,
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
                let cleanup = session::rdp::drop_session(&s, &token).await;
                if let Some(c) = cleanup {
                    let s2 = app.state::<AppState>();
                    run_cleanup(&s2, c).await;
                }
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

struct ResolvedRdpCredential {
    password: Zeroizing<String>,
    /// LDAP bind modes return the canonical username; the caller
    /// swaps it in over the profile's username field.
    effective_username: Option<String>,
    /// LDAP operator-bind can encode `DOMAIN\username` or
    /// `user@realm` — we surface the parsed domain part here so
    /// the RDP connector can put it in the right slot.
    domain: Option<String>,
    on_close: Option<crate::session::SessionCleanup>,
}

async fn resolve_rdp_credential(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile: &Value,
    operator_credential: Option<&OperatorCredential>,
) -> Result<ResolvedRdpCredential, CommandError> {
    let cs = profile.get("credential_source").ok_or_else(|| {
        CommandError::from("profile is missing credential_source".to_string())
    })?;
    let kind = cs.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    match kind {
        "secret" => {
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
            Ok(ResolvedRdpCredential {
                password: Zeroizing::new(password),
                effective_username: data
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .filter(|s| !s.is_empty()),
                domain: None,
                on_close: None,
            })
        }
        "ldap" => {
            let ldap_mount = ldap_mount_prefix(cs)?;
            let bind_mode = cs
                .get("bind_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("operator");
            match bind_mode {
                "operator" => {
                    let oc = operator_credential.ok_or_else(|| {
                        CommandError::from(
                            "ldap bind_mode = operator requires operator_credential on the open request"
                                .to_string(),
                        )
                    })?;
                    if oc.username.is_empty() || oc.password.is_empty() {
                        return Err(CommandError::from(
                            "operator-supplied LDAP credential must carry both username and password"
                                .to_string(),
                        ));
                    }
                    let (effective_user, domain) = split_domain_user(&oc.username);
                    let _ = ldap_mount;
                    Ok(ResolvedRdpCredential {
                        password: Zeroizing::new(oc.password.clone()),
                        effective_username: Some(effective_user),
                        domain,
                        on_close: None,
                    })
                }
                "static_role" => {
                    let role = cs
                        .get("static_role")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            CommandError::from(
                                "ldap bind_mode = static_role requires credential_source.static_role"
                                    .to_string(),
                            )
                        })?;
                    let path = format!("{ldap_mount}static-cred/{role}");
                    let resp = make_request(state, Operation::Read, path, None).await?;
                    let data: HashMap<String, Value> = resp
                        .and_then(|r| r.data)
                        .map(|m| m.into_iter().collect())
                        .unwrap_or_default();
                    let username = data
                        .get("username")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!(
                            "ldap static-cred/{role} missing `username`"
                        )))?
                        .to_string();
                    let password = data
                        .get("password")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!(
                            "ldap static-cred/{role} missing `password`"
                        )))?
                        .to_string();
                    let (effective_user, domain) = split_domain_user(&username);
                    Ok(ResolvedRdpCredential {
                        password: Zeroizing::new(password),
                        effective_username: Some(effective_user),
                        domain,
                        on_close: None,
                    })
                }
                "library_set" => {
                    let set = cs
                        .get("library_set")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            CommandError::from(
                                "ldap bind_mode = library_set requires credential_source.library_set"
                                    .to_string(),
                            )
                        })?;
                    let path = format!("{ldap_mount}library/{set}/check-out");
                    let resp = make_request(state, Operation::Write, path, None).await?;
                    let data: HashMap<String, Value> = resp
                        .and_then(|r| r.data)
                        .map(|m| m.into_iter().collect())
                        .unwrap_or_default();
                    let username = data
                        .get("username")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!(
                            "ldap library/{set}/check-out missing `username`"
                        )))?
                        .to_string();
                    let password = data
                        .get("password")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!(
                            "ldap library/{set}/check-out missing `password`"
                        )))?
                        .to_string();
                    let lease_id = data
                        .get("lease_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CommandError::from(format!(
                            "ldap library/{set}/check-out missing `lease_id`"
                        )))?
                        .to_string();
                    let (effective_user, domain) = split_domain_user(&username);
                    Ok(ResolvedRdpCredential {
                        password: Zeroizing::new(password),
                        effective_username: Some(effective_user),
                        domain,
                        on_close: Some(crate::session::SessionCleanup {
                            kind: crate::session::SessionCleanupKind::LdapLibraryCheckIn {
                                ldap_mount: ldap_mount.trim_end_matches('/').to_string(),
                                library_set: set.to_string(),
                                lease_id,
                            },
                        }),
                    })
                }
                other => Err(CommandError::from(format!(
                    "unknown ldap bind_mode `{other}`"
                ))),
            }
        }
        other => Err(CommandError::from(format!(
            "credential source `{other}` lands in a later phase"
        ))),
    }
}

/// Split `DOMAIN\\user` or `user@realm` into `(user, Some(domain))`,
/// otherwise return `(input, None)`. RDP CredSSP wants domain in
/// its own field, even though most servers tolerate the combined
/// form.
fn split_domain_user(input: &str) -> (String, Option<String>) {
    if let Some((domain, user)) = input.split_once('\\') {
        if !domain.is_empty() && !user.is_empty() {
            return (user.to_string(), Some(domain.to_string()));
        }
    }
    if let Some((user, realm)) = input.rsplit_once('@') {
        if !user.is_empty() && !realm.is_empty() {
            return (user.to_string(), Some(realm.to_string()));
        }
    }
    (input.to_string(), None)
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
    // returns an error we ignore. drop_session removes either kind
    // and yields any captured cleanup hook.
    let _ = session::ssh::send_control(&state, &request.token, SshControl::Close).await;
    let _ = session::rdp::send_control(
        &state,
        &request.token,
        session::rdp::RdpControl::Close,
    )
    .await;
    let cleanup_ssh = session::ssh::drop_session(&state, &request.token).await;
    let cleanup_rdp = session::rdp::drop_session(&state, &request.token).await;
    if let Some(c) = cleanup_ssh.or(cleanup_rdp) {
        run_cleanup(&state, c).await;
    }
    Ok(())
}

/// Execute a session-close cleanup hook. LDAP library check-in is
/// the only kind today; failures log a warning and swallow the
/// error — the alternative would be to fail the close and leave
/// the session record dangling, which is worse.
async fn run_cleanup(state: &State<'_, AppState>, cleanup: crate::session::SessionCleanup) {
    match cleanup.kind {
        crate::session::SessionCleanupKind::LdapLibraryCheckIn {
            ldap_mount,
            library_set,
            lease_id,
        } => {
            let path = format!("{ldap_mount}/library/{library_set}/check-in");
            let mut body = Map::new();
            body.insert("lease_id".into(), Value::String(lease_id.clone()));
            match make_request(state, Operation::Write, path, Some(body)).await {
                Ok(_) => log::info!(
                    "resource-connect: ldap library check-in ok (mount={ldap_mount} set={library_set} lease={lease_id})"
                ),
                Err(e) => log::warn!(
                    "resource-connect: ldap library check-in failed (mount={ldap_mount} set={library_set} lease={lease_id}): {e:?}"
                ),
            }
        }
    }
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

struct ResolvedSshCredential {
    credential: SshCredential,
    /// When the resolver knows the canonical username (e.g.
    /// LDAP static-role / library check-out returns one), the
    /// caller swaps it in over the profile's username.
    effective_username: Option<String>,
    /// LDAP library check-out registers a cleanup hook here so
    /// `session_close` can return the account to the pool.
    on_close: Option<crate::session::SessionCleanup>,
}

async fn resolve_ssh_credential(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile: &Value,
    operator_credential: Option<&OperatorCredential>,
) -> Result<ResolvedSshCredential, CommandError> {
    let cs = profile.get("credential_source").ok_or_else(|| {
        CommandError::from("profile is missing credential_source".to_string())
    })?;
    let kind = cs.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    match kind {
        "secret" => resolve_secret_ssh(state, resource_name, cs).await,
        "ldap" => resolve_ldap_ssh(state, cs, operator_credential).await,
        "ssh-engine" | "pki" => Err(CommandError::from(format!(
            "credential source `{kind}` lands in a later phase"
        ))),
        other => Err(CommandError::from(format!(
            "unknown credential source `{other}`"
        ))),
    }
}

async fn resolve_secret_ssh(
    state: &State<'_, AppState>,
    resource_name: &str,
    cs: &Value,
) -> Result<ResolvedSshCredential, CommandError> {
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

    let credential = if !private_key.is_empty() {
        SshCredential::PrivateKey {
            pem: Zeroizing::new(private_key),
            passphrase: if passphrase.is_empty() {
                None
            } else {
                Some(Zeroizing::new(passphrase))
            },
        }
    } else if !password.is_empty() {
        SshCredential::Password(Zeroizing::new(password))
    } else {
        return Err(CommandError::from(format!(
            "secret `{secret_id}` carries no `password` or `private_key` field — Connect can't authenticate"
        )));
    };
    Ok(ResolvedSshCredential {
        credential,
        effective_username: data
            .get("username")
            .and_then(|v| v.as_str())
            .map(String::from)
            .filter(|s| !s.is_empty()),
        on_close: None,
    })
}

/// Resolve an LDAP-source profile to an SSH-shaped credential.
///
/// Three sub-modes:
///   - `operator` — operator types user+password into a frontend
///     prompt; we forward verbatim. (We don't run an extra
///     simple-bind validation here; the SSH server itself will
///     bounce bad creds back to the operator.)
///   - `static_role` — internal request to the bound LDAP mount's
///     `/static-cred/<role>` endpoint pulls the vault-managed
///     username + password.
///   - `library_set` — internal request to
///     `/library/<set>/check-out`; we register a session-close
///     hook that calls `/library/<set>/check-in` with the
///     captured `lease_id`.
async fn resolve_ldap_ssh(
    state: &State<'_, AppState>,
    cs: &Value,
    operator_credential: Option<&OperatorCredential>,
) -> Result<ResolvedSshCredential, CommandError> {
    let ldap_mount = ldap_mount_prefix(cs)?;
    let bind_mode = cs
        .get("bind_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("operator");
    match bind_mode {
        "operator" => {
            let oc = operator_credential.ok_or_else(|| {
                CommandError::from(
                    "ldap bind_mode = operator requires operator_credential on the open request"
                        .to_string(),
                )
            })?;
            if oc.username.is_empty() || oc.password.is_empty() {
                return Err(CommandError::from(
                    "operator-supplied LDAP credential must carry both username and password"
                        .to_string(),
                ));
            }
            // We don't run an extra LDAP simple-bind validation
            // here — adding one would double the round-trip on
            // every connect and the SSH server validates these
            // against AD anyway. If operator demand calls for an
            // explicit pre-flight, it's a one-line addition that
            // hits the existing `ldap/check-connection` style
            // path on the bound mount.
            let _ = ldap_mount;
            Ok(ResolvedSshCredential {
                credential: SshCredential::Password(Zeroizing::new(oc.password.clone())),
                effective_username: Some(oc.username.clone()),
                on_close: None,
            })
        }
        "static_role" => {
            let role = cs
                .get("static_role")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    CommandError::from(
                        "ldap bind_mode = static_role requires credential_source.static_role"
                            .to_string(),
                    )
                })?;
            let path = format!("{ldap_mount}static-cred/{role}");
            let resp = make_request(state, Operation::Read, path, None).await?;
            let data: HashMap<String, Value> = resp
                .and_then(|r| r.data)
                .map(|m| m.into_iter().collect())
                .unwrap_or_default();
            let username = data
                .get("username")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    CommandError::from(format!(
                        "ldap static-cred/{role} missing `username`"
                    ))
                })?
                .to_string();
            let password = data
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    CommandError::from(format!(
                        "ldap static-cred/{role} missing `password`"
                    ))
                })?
                .to_string();
            Ok(ResolvedSshCredential {
                credential: SshCredential::Password(Zeroizing::new(password)),
                effective_username: Some(username),
                on_close: None,
            })
        }
        "library_set" => {
            let set = cs
                .get("library_set")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    CommandError::from(
                        "ldap bind_mode = library_set requires credential_source.library_set"
                            .to_string(),
                    )
                })?;
            let path = format!("{ldap_mount}library/{set}/check-out");
            let resp = make_request(state, Operation::Write, path, None).await?;
            let data: HashMap<String, Value> = resp
                .and_then(|r| r.data)
                .map(|m| m.into_iter().collect())
                .unwrap_or_default();
            let username = data
                .get("username")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    CommandError::from(format!(
                        "ldap library/{set}/check-out missing `username`"
                    ))
                })?
                .to_string();
            let password = data
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    CommandError::from(format!(
                        "ldap library/{set}/check-out missing `password`"
                    ))
                })?
                .to_string();
            let lease_id = data
                .get("lease_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    CommandError::from(format!(
                        "ldap library/{set}/check-out missing `lease_id`"
                    ))
                })?
                .to_string();
            Ok(ResolvedSshCredential {
                credential: SshCredential::Password(Zeroizing::new(password)),
                effective_username: Some(username),
                on_close: Some(crate::session::SessionCleanup {
                    kind: crate::session::SessionCleanupKind::LdapLibraryCheckIn {
                        ldap_mount: ldap_mount.trim_end_matches('/').to_string(),
                        library_set: set.to_string(),
                        lease_id,
                    },
                }),
            })
        }
        other => Err(CommandError::from(format!(
            "unknown ldap bind_mode `{other}` (expected operator / static_role / library_set)"
        ))),
    }
}

/// Mount-path prefix for an LDAP credential source. Always ends
/// with `/`. The profile field is operator-typed, so we trim
/// stray whitespace and ensure exactly one trailing slash.
fn ldap_mount_prefix(cs: &Value) -> Result<String, CommandError> {
    let raw = cs
        .get("ldap_mount")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| CommandError::from("credential_source.ldap_mount is required"))?;
    if raw.is_empty() {
        return Err(CommandError::from(
            "credential_source.ldap_mount must not be empty".to_string(),
        ));
    }
    let trimmed = raw.trim_end_matches('/');
    Ok(format!("{trimmed}/"))
}
