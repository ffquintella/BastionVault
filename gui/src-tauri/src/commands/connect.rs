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

// Resource module is mounted at `resources/`; the engine itself
// nests records under `resources/resources/<name>` and secrets
// under `resources/secrets/<name>/<key>`. We carry only the mount
// prefix here so each call site can pick the right sub-path —
// matches the convention in `commands/resources.rs` (which uses
// the same `RESOURCE_MOUNT = "resources/"`).
const RESOURCE_MOUNT: &str = "resources/";

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
    let host_candidates = profile_host_candidates(&profile, &meta);
    if host_candidates.is_empty() {
        return Err(CommandError::from("resource has no hostname or ip_address; set one or override target_host on the profile".to_string()));
    }
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
    // Walk the host candidates in order (IP before hostname when
    // both are set on the resource). Fall back to the next candidate
    // only on network-layer failures — auth rejections short-circuit
    // so we don't burn auth attempts on every candidate.
    let on_close = resolved.on_close;
    let (chosen_host, outcome): (String, SshOpenOutcome) = {
        let mut last_err: Option<String> = None;
        let mut found: Option<(String, SshOpenOutcome)> = None;
        for (idx, host) in host_candidates.iter().enumerate() {
            let is_last = idx + 1 == host_candidates.len();
            let label = format!("ssh {username}@{host}:{port}");
            let res = tokio::time::timeout(
                CONNECT_TIMEOUT,
                open_ssh_session(
                    app.clone(),
                    &state,
                    SshOpenArgs {
                        host: host.clone(),
                        port,
                        username: username.clone(),
                        credential: credential.clone(),
                        host_key_fingerprint: host_key_fingerprint.clone(),
                        label: label.clone(),
                        on_close: on_close.clone(),
                    },
                ),
            )
            .await;
            match res {
                Ok(Ok(o)) => {
                    found = Some((host.clone(), o));
                    break;
                }
                Ok(Err(e)) => {
                    if !is_last && is_connect_layer_error(&e) {
                        log::warn!(
                            "resource-connect/ssh: candidate {host}:{port} failed at network layer ({e}); trying next"
                        );
                        last_err = Some(e);
                        continue;
                    }
                    return Err(CommandError::from(e));
                }
                Err(_) => {
                    let msg = format!(
                        "ssh: connect+auth to {host}:{port} timed out after {}s",
                        CONNECT_TIMEOUT.as_secs()
                    );
                    if !is_last {
                        log::warn!("resource-connect/ssh: {msg}; trying next candidate");
                        last_err = Some(msg);
                        continue;
                    }
                    return Err(CommandError::from(msg));
                }
            }
        }
        found.ok_or_else(|| CommandError::from(
            last_err.unwrap_or_else(|| "ssh: no host candidates succeeded".into())
        ))?
    };
    let host = chosen_host;
    let label = format!("ssh {username}@{host}:{port}");

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

    let _ = record_recent_session(
        &state,
        &request.resource_name,
        &profile,
        SessionProtocolTag::Ssh,
    )
    .await;

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
    let host_candidates = profile_host_candidates(&profile, &meta);
    if host_candidates.is_empty() {
        return Err(CommandError::from(
            "resource has no hostname or ip_address; set one or override target_host on the profile"
                .to_string(),
        ));
    }
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
    let on_close = resolved.on_close;
    let credential = resolved.credential;
    let domain = resolved.domain;
    let aggressive_performance = profile
        .get("rdp_aggressive_performance")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Walk the host candidates in order — IP first when present,
    // hostname as fallback. Only network-layer failures fall through
    // to the next candidate.
    let (host, outcome) = {
        let mut last_err: Option<String> = None;
        let mut found: Option<(String, session::rdp::RdpOpenOutcome)> = None;
        for (idx, host) in host_candidates.iter().enumerate() {
            let is_last = idx + 1 == host_candidates.len();
            let label = format!("rdp {username}@{host}:{port}");
            let res = session::rdp::open_rdp_session(
                app.clone(),
                &state,
                session::rdp::RdpOpenArgs {
                    host: host.clone(),
                    port,
                    username: username.clone(),
                    credential: credential.clone(),
                    domain: domain.clone(),
                    label,
                    on_close: on_close.clone(),
                    aggressive_performance,
                },
            )
            .await;
            match res {
                Ok(o) => {
                    found = Some((host.clone(), o));
                    break;
                }
                Err(e) => {
                    if !is_last && is_connect_layer_error(&e) {
                        log::warn!(
                            "resource-connect/rdp: candidate {host}:{port} failed at network layer ({e}); trying next"
                        );
                        last_err = Some(e);
                        continue;
                    }
                    return Err(CommandError::from(e));
                }
            }
        }
        found.ok_or_else(|| CommandError::from(
            last_err.unwrap_or_else(|| "rdp: no host candidates succeeded".into())
        ))?
    };
    let label = format!("rdp {username}@{host}:{port}");

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

    let _ = record_recent_session(
        &state,
        &request.resource_name,
        &profile,
        SessionProtocolTag::Rdp,
    )
    .await;

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
    credential: session::rdp::RdpCredential,
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
                credential: session::rdp::RdpCredential::Password(Zeroizing::new(password)),
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
                        credential: session::rdp::RdpCredential::Password(Zeroizing::new(oc.password.clone())),
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
                        credential: session::rdp::RdpCredential::Password(Zeroizing::new(password)),
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
                        credential: session::rdp::RdpCredential::Password(Zeroizing::new(password)),
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
        "pki" => {
            let issued = issue_pki_credential(state, resource_name, cs).await?;
            let certificate_der = pem_body_to_der(&issued.certificate, "CERTIFICATE")?;
            let private_key_der =
                pem_body_to_der(&issued.private_key, "PRIVATE KEY")
                    // RSA private keys often come in PEM-wrapped
                    // PKCS#1 form (`-----BEGIN RSA PRIVATE KEY-----`)
                    // — accept both forms and let the IronRDP
                    // connector's PKCS#8/PKCS#1 fallback sort it out.
                    .or_else(|_| pem_body_to_der(&issued.private_key, "RSA PRIVATE KEY"))?;
            log::info!(
                "resource-connect/rdp: pki/issue produced cert (serial {}) — wiring as CredSSP smartcard",
                issued.serial_number
            );
            Ok(ResolvedRdpCredential {
                credential: session::rdp::RdpCredential::SmartCard(
                    session::rdp::SmartCardCredential {
                        certificate_der,
                        private_key_der,
                        // Synthetic PIN — the PIV emulator inside
                        // sspi-rs accepts any non-empty value
                        // since there's no hardware to enforce it.
                        pin: "0000".to_string(),
                    },
                ),
                effective_username: None, // smart-card cred carries the UPN itself
                domain: None,
                on_close: None,
            })
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
    let path = format!("{RESOURCE_MOUNT}resources/{name}");
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

/// Ordered list of host candidates to try when opening a session.
///
/// Preference order:
///   1. Profile `target_host` override (operator-set; trumps everything).
///   2. Resource `ip_address` (avoids DNS, fastest path).
///   3. Resource `hostname` (DNS fallback).
///
/// Duplicates are dropped so a profile that pins `target_host` to
/// the same value as the resource's IP doesn't double-try.
fn profile_host_candidates(profile: &Value, meta: &Map<String, Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        if !s.is_empty() && !out.iter().any(|h| h == s) {
            out.push(s.to_string());
        }
    };
    if let Some(s) = profile.get("target_host").and_then(|v| v.as_str()) {
        push(s);
    }
    if let Some(s) = meta.get("ip_address").and_then(|v| v.as_str()) {
        push(s);
    }
    if let Some(s) = meta.get("hostname").and_then(|v| v.as_str()) {
        push(s);
    }
    out
}

/// Heuristic: did the open fail at the network layer (DNS / TCP / TLS)
/// rather than at auth / protocol layer? Only network failures justify
/// falling back to the next host candidate — re-trying after an auth
/// rejection would just lock the account on the next host.
fn is_connect_layer_error(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.starts_with("connect ")
        || e.contains("tcp connect")
        || e.contains("parse/resolve")
        || e.contains("dns lookup")
        || e.contains("tls upgrade")
        || e.contains("connect_begin")
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
        "pki" => resolve_pki_ssh(state, resource_name, cs).await,
        "ssh-engine" => Err(CommandError::from(
            "credential source `ssh-engine` lands in a later phase".to_string(),
        )),
        other => Err(CommandError::from(format!(
            "unknown credential source `{other}`"
        ))),
    }
}

/// Resolve a PKI-source profile for SSH: call `pki/issue/<role>`
/// against the bound PKI mount with the resource hostname as the
/// requested CN, then feed the returned `private_key` PEM to
/// russh as a publickey credential. The cert itself is delivered
/// alongside (operators using x509-cert-auth servers like Tectia
/// drop it on the host; everyone else relies on the public key
/// being in `authorized_keys`).
///
/// The cert is **short-lived** by virtue of the PKI role's
/// `max_ttl` — operators get the lifecycle benefit (auto-rotation
/// per session) even when the SSH server treats the credential
/// as a plain key.
async fn resolve_pki_ssh(
    state: &State<'_, AppState>,
    resource_name: &str,
    cs: &Value,
) -> Result<ResolvedSshCredential, CommandError> {
    let issued = issue_pki_credential(state, resource_name, cs).await?;
    Ok(ResolvedSshCredential {
        credential: SshCredential::PrivateKey {
            pem: Zeroizing::new(issued.private_key),
            passphrase: None,
        },
        // Don't override the profile.username — the PKI cert's CN
        // is the hostname, not the OS user the operator wants to
        // log in as. Profile.username stays authoritative.
        effective_username: None,
        on_close: None,
    })
}

/// Pulled out so the SSH and RDP paths share the issue-call
/// shape. `certificate` / `issuing_ca` / `serial_number` are kept
/// alongside `private_key` so the future RDP CredSSP smartcard
/// path can wrap them as a synthetic PIV credential without
/// re-issuing.
#[allow(dead_code)]
struct PkiIssued {
    certificate: String,
    private_key: String,
    issuing_ca: String,
    serial_number: String,
}

async fn issue_pki_credential(
    state: &State<'_, AppState>,
    resource_name: &str,
    cs: &Value,
) -> Result<PkiIssued, CommandError> {
    let pki_mount = pki_mount_prefix(cs)?;
    let pki_role = cs
        .get("pki_role")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CommandError::from("credential_source.pki_role is required"))?;
    // Default CN: the resource's hostname (or ip_address fallback).
    // Operators with non-DNS subjects can override via the role's
    // CSR / template.
    let meta = read_resource_meta(state, resource_name).await?;
    let cn = meta
        .get("hostname")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| meta.get("ip_address").and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
        .map(String::from)
        .unwrap_or_else(|| resource_name.to_string());

    let mut body = Map::new();
    body.insert("common_name".into(), Value::String(cn));
    if let Some(alt) = cs.get("alt_names").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        body.insert("alt_names".into(), Value::String(alt.to_string()));
    }
    if let Some(ttl) = cs
        .get("cert_ttl_secs")
        .and_then(|v| v.as_u64())
        .filter(|n| *n > 0)
    {
        body.insert("ttl".into(), Value::String(format!("{ttl}s")));
    }

    let path = format!("{pki_mount}issue/{pki_role}");
    let resp = make_request(state, Operation::Write, path, Some(body)).await?;
    let data: HashMap<String, Value> = resp
        .and_then(|r| r.data)
        .map(|m| m.into_iter().collect())
        .unwrap_or_default();
    let private_key = data
        .get("private_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::from(format!(
            "pki/{pki_role} issue response missing `private_key`"
        )))?
        .to_string();
    let certificate = data
        .get("certificate")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::from(format!(
            "pki/{pki_role} issue response missing `certificate`"
        )))?
        .to_string();
    let issuing_ca = data
        .get("issuing_ca")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default();
    let serial_number = data
        .get("serial_number")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default();
    Ok(PkiIssued {
        certificate,
        private_key,
        issuing_ca,
        serial_number,
    })
}

/// Decode a PEM block into the underlying DER bytes. We don't
/// pull in a full PEM crate for this; the format is trivial and
/// we already control both producers (the in-tree PKI engine).
/// Returns `Err` if the expected `BEGIN <label>` marker isn't
/// found or the base64 body fails to decode.
fn pem_body_to_der(pem: &str, label: &str) -> Result<Vec<u8>, CommandError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .ok_or_else(|| CommandError::from(format!("pem: missing `{begin}`")))?
        + begin.len();
    let stop = pem
        .find(&end)
        .ok_or_else(|| CommandError::from(format!("pem: missing `{end}`")))?;
    if stop <= start {
        return Err(CommandError::from(format!("pem: malformed `{label}`")));
    }
    let body: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD
        .decode(body.as_bytes())
        .map_err(|e| CommandError::from(format!("pem: base64 decode `{label}`: {e}")))
}

fn pki_mount_prefix(cs: &Value) -> Result<String, CommandError> {
    let raw = cs
        .get("pki_mount")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| CommandError::from("credential_source.pki_mount is required"))?;
    if raw.is_empty() {
        return Err(CommandError::from(
            "credential_source.pki_mount must not be empty".to_string(),
        ));
    }
    let trimmed = raw.trim_end_matches('/');
    Ok(format!("{trimmed}/"))
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

// ── Recently-connected list (Phase 7) ──────────────────────────────

/// Cap on the persisted recently-connected list. Keeps the
/// resource record bounded — every operator who clicks Connect
/// appends one entry, so without a cap a long-lived production
/// host's metadata would grow without bound.
const RECENT_SESSIONS_CAP: usize = 10;

#[derive(Copy, Clone)]
enum SessionProtocolTag {
    Ssh,
    Rdp,
}

impl SessionProtocolTag {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
        }
    }
}

/// Append a recently-connected entry on the resource's metadata
/// record. Best-effort: a failed write logs at WARN and is
/// otherwise swallowed — losing a recently-connected entry is
/// far less bad than failing the actual session-open after the
/// transport is already up.
async fn record_recent_session(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile: &Value,
    protocol: SessionProtocolTag,
) -> Result<(), CommandError> {
    let mut meta = read_resource_meta(state, resource_name).await?;
    let mut recent: Vec<Value> = meta
        .get("recent_sessions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let actor = caller_display(state).await;
    let entry = serde_json::json!({
        "ts": now_rfc3339(),
        "profile_id": profile.get("id").and_then(|v| v.as_str()).unwrap_or(""),
        "profile_name": profile.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        "actor": actor,
        "protocol": protocol.as_str(),
    });
    recent.insert(0, entry); // newest first
    if recent.len() > RECENT_SESSIONS_CAP {
        recent.truncate(RECENT_SESSIONS_CAP);
    }
    meta.insert("recent_sessions".into(), Value::Array(recent));
    let path = format!("{RESOURCE_MOUNT}resources/{resource_name}");
    let _ = make_request(state, Operation::Write, path, Some(meta))
        .await
        .map_err(|e| {
            log::warn!(
                "resource-connect: record_recent_session for `{resource_name}` failed: {e:?}"
            );
            e
        });
    Ok(())
}

fn now_rfc3339() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let tm = libc_time_breakdown(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.year, tm.mon, tm.mday, tm.hour, tm.minute, tm.second
    )
}

struct BrokenDownTime {
    year: i32,
    mon: u32,
    mday: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

/// Tiny gmtime breakdown so we don't pull `time` / `chrono` for
/// one timestamp formatter. Good enough for the year range we
/// care about (1970..2099). Mirrors the same approach the
/// resource module uses in its history-log path.
fn libc_time_breakdown(unix: i64) -> BrokenDownTime {
    let mut secs = unix.max(0) as u64;
    let second = (secs % 60) as u32;
    secs /= 60;
    let minute = (secs % 60) as u32;
    secs /= 60;
    let hour = (secs % 24) as u32;
    let mut days = secs / 24;
    let mut year = 1970i32;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let months = [
        31u64,
        if is_leap(year) { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut mon = 1u32;
    for &dm in &months {
        if days < dm {
            break;
        }
        days -= dm;
        mon += 1;
    }
    BrokenDownTime {
        year,
        mon,
        mday: days as u32 + 1,
        hour,
        minute,
        second,
    }
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

async fn caller_display(state: &State<'_, AppState>) -> String {
    match make_request(state, Operation::Read, "auth/token/lookup-self".to_string(), None).await {
        Ok(Some(resp)) => {
            let data = resp.data.unwrap_or_default();
            data.get("display_name")
                .and_then(|v| v.as_str())
                .or_else(|| data.get("entity_id").and_then(|v| v.as_str()))
                .or_else(|| data.get("id").and_then(|v| v.as_str()))
                .unwrap_or("unknown")
                .to_string()
        }
        _ => "unknown".to_string(),
    }
}
