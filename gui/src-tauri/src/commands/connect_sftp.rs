//! Tauri commands for SFTP connection profiles (features/sftp-connect.md).
//!
//! `session_open_sftp` reuses the SSH open path's building blocks — profile
//! lookup, connect-time MFA, `resolve_ssh_credential` (and with it the SSH
//! login-class rule), host candidates, host-key pinning — and differs in
//! three ways:
//!
//! * **Direct only.** When the effective Rustion policy would route the
//!   session through a bastion the open is refused; it is never dialled
//!   direct instead. No bastion accepts the `sftp` subsystem yet.
//! * **No `provider` source.** `connect/authorize` releases provider
//!   accounts for ssh / rdp / web only.
//! * **Always its own window** (`sftp-<token>`), never a workspace pane.
//!
//! Every other command here is called by that window, takes the session
//! token, and is refused unless the calling window holds that session
//! (`require_session_window`). The local-filesystem commands are therefore
//! unusable without a live SFTP session in the calling window.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, State, Webview};

use super::connect::{
    collect_policy_hints, find_profile, is_connect_layer_error, open_context, profile_host_candidates, profile_port,
    profile_username, read_effective_policy, read_resource_meta, record_recent_session, require_session_window,
    resolve_session_layout, resolve_ssh_credential, spawn_own_session_window, now_rfc3339, OperatorCredential,
    SessionProtocolTag,
};
use super::connect_provider::{dial_in_order, DialFailure};
use crate::error::{CmdResult, CommandError};
use crate::session::{
    self,
    attachments::SessionDescriptor,
    sftp::{self as sftp_session, Direction, Listing, SftpOpenArgs, SftpOpenOutcome, TransferOutcome, TransferRequest},
    ssh::CONNECT_TIMEOUT,
    workspace::Placement,
    SessionState,
};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SftpOpenRequest {
    pub resource_name: String,
    pub profile_id: String,
    /// LDAP operator-bind profiles only, as for SSH.
    #[serde(default)]
    pub operator_credential: Option<OperatorCredential>,
    /// Single-use connect-time MFA ticket, as for SSH.
    #[serde(default)]
    pub connect_ticket: Option<String>,
}

#[derive(Serialize)]
pub struct SftpOpenResponse {
    pub token: String,
    pub closed_event: String,
    pub window_label: String,
}

/// Why an SFTP open may not take the transport the policy asks for.
/// `None` = dial direct.
fn transport_refusal(transport: &str, bastions: &[String]) -> Option<String> {
    let brokered = match transport {
        "rustion-required" => true,
        "rustion-preferred" => !bastions.is_empty(),
        _ => false,
    };
    brokered.then(|| {
        format!(
            "SFTP sessions can't go through a Rustion bastion yet, and this resource's effective transport is \
             `{transport}`; refusing to dial it direct. Use an SSH profile, or ask an administrator to change the \
             resource's transport policy."
        )
    })
}

#[tauri::command]
pub async fn session_open_sftp(
    state: State<'_, AppState>,
    app: AppHandle,
    request: SftpOpenRequest,
) -> CmdResult<SftpOpenResponse> {
    let opened_in = open_context(&state, None).await?;
    let meta = read_resource_meta(&state, &request.resource_name).await?;
    let profile = find_profile(&meta, &request.profile_id).ok_or_else(|| {
        CommandError::from(format!("profile `{}` not found on resource `{}`", request.profile_id, request.resource_name))
    })?;
    session::ProfileProtocol::require(&profile, session::ProfileProtocol::Sftp).map_err(CommandError::from)?;
    // Own window, always; the preferences are read for the window builder
    // (macOS native tabs) only.
    let (_, layout_prefs) = resolve_session_layout(Some(Placement::OwnWindow))?;

    let kind = profile.pointer("/credential_source/kind").and_then(Value::as_str).unwrap_or("");
    if kind == "provider" {
        return Err(CommandError::from(
            "SFTP profiles can't use a credential provider yet; pick a stored secret, LDAP, PKI or SSH-engine source"
                .to_string(),
        ));
    }

    let host_candidates = profile_host_candidates(&profile, &meta);
    if host_candidates.is_empty() {
        return Err(CommandError::from(
            "resource has no hostname or ip_address; set one or override target_host on the profile".to_string(),
        ));
    }
    let port = profile_port(&profile);
    let host_key_fingerprint = profile.get("host_key_pin").and_then(Value::as_str).unwrap_or("").to_string();

    // Transport tier before anything is redeemed or resolved: a session the
    // policy wants brokered is refused, never downgraded to direct.
    let (resource_id, resource_type, asset_group_ids) =
        collect_policy_hints(&state, &request.resource_name, &meta).await;
    let effective = read_effective_policy(&state, &resource_id, &resource_type, &asset_group_ids).await?;
    if let Some(detail) = &effective.lock_violation {
        return Err(CommandError::from(format!("rustion policy lock violation: {detail}")));
    }
    if let Some(refusal) = transport_refusal(&effective.transport, &effective.bastions) {
        log::warn!(
            target: "audit",
            "session.open.refused: resource={} profile={} protocol=sftp reason=brokered_transport transport={}",
            request.resource_name,
            request.profile_id,
            effective.transport,
        );
        return Err(CommandError::from(refusal));
    }

    // Connect-time MFA: the ticket is redeemed before any credential is
    // resolved or minted, exactly as on the SSH direct path.
    super::connect_mfa::authorize_direct(
        &state,
        &request.resource_name,
        &request.profile_id,
        request.connect_ticket.as_deref(),
    )
    .await?;
    let (resolved, login_class) = resolve_ssh_credential(
        &state,
        &app,
        &request.resource_name,
        &profile,
        &meta,
        request.operator_credential.as_ref(),
    )
    .await?;
    let username = resolved.effective_username.clone().unwrap_or_else(|| profile_username(&profile));
    if username.is_empty() {
        return Err(CommandError::from(
            "SFTP profile has no username (set profile.username, use a `default-account` or LDAP credential \
             source, or give the ssh-engine role a `default_user`)"
                .to_string(),
        ));
    }
    let credential = resolved.credential;
    let on_close = resolved.on_close;

    let (host, outcome): (String, SftpOpenOutcome) = dial_in_order("sftp", &host_candidates, port, |host| {
        let app = app.clone();
        let state = &state;
        let args = SftpOpenArgs {
            host: host.clone(),
            port,
            username: username.clone(),
            credential: credential.clone(),
            host_key_fingerprint: host_key_fingerprint.clone(),
            label: format!("sftp {username}@{host}:{port}"),
            on_close: on_close.clone(),
        };
        async move {
            match tokio::time::timeout(CONNECT_TIMEOUT, sftp_session::open_sftp_session(app, state, args)).await {
                Ok(Ok(o)) => Ok(o),
                Ok(Err(e)) => Err(DialFailure { network_layer: is_connect_layer_error(&e), message: e }),
                Err(_) => Err(DialFailure {
                    message: format!(
                        "sftp: connect+auth to {host}:{port} timed out after {}s",
                        CONNECT_TIMEOUT.as_secs()
                    ),
                    network_layer: true,
                }),
            }
        }
    })
    .await?;
    let label = format!("sftp {username}@{host}:{port}");

    let (mode, serial) = match &resolved.engine_mint {
        Some(m) => (m.mode.as_str(), m.cert_serial.as_deref().unwrap_or("")),
        None => ("", ""),
    };
    log::info!(
        target: "audit",
        "session.open: resource={} protocol=sftp login_class={} login_class_source={} ssh_engine_mode={} \
         cert_serial={} login_class_chain=[{}] token={} host={}:{}",
        request.resource_name,
        login_class.login_class,
        login_class.login_class_source,
        mode,
        serial,
        login_class.login_class_chain.join(","),
        outcome.token,
        host,
        port,
    );

    let descriptor = SessionDescriptor {
        token: outcome.token.clone(),
        protocol: session::ProfileProtocol::Sftp,
        label: label.clone(),
        resource_name: request.resource_name.clone(),
        profile_id: request.profile_id.clone(),
        stdout_event: None,
        closed_event: outcome.closed_event.clone(),
        resize_event: None,
        cursor_event: None,
        width: None,
        height: None,
        opened_at: now_rfc3339(),
        placement: Placement::OwnWindow,
        pane_ref: None,
        namespace: opened_in.namespace.clone(),
        vault_id: opened_in.vault_id.clone(),
    };
    let window_label = spawn_own_session_window(&app, &state, descriptor, &layout_prefs).await?;
    log::info!("resource-connect/sftp: session for {label} rendered in window {window_label}");

    let _ = record_recent_session(&state, &request.resource_name, &profile, SessionProtocolTag::Sftp).await;

    Ok(SftpOpenResponse { token: outcome.token, closed_event: outcome.closed_event, window_label })
}

/// The live SFTP session behind `token`, for the window that holds it.
async fn session_for(state: &State<'_, AppState>, webview: &Webview, token: &str) -> CmdResult<Arc<SftpSession>> {
    require_session_window(state, webview, token).await?;
    match state.connect_sessions.lock().await.get(token) {
        Some(SessionState::Sftp(s)) => Ok(Arc::clone(&s.sftp)),
        Some(_) => Err(CommandError::from(format!("session `{token}` is not an SFTP session"))),
        None => Err(CommandError::from("the SFTP session has ended".to_string())),
    }
}

#[derive(Deserialize)]
pub struct SftpTokenRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct SftpPathRequest {
    pub token: String,
    pub path: String,
}

#[derive(Deserialize)]
pub struct SftpNameRequest {
    pub token: String,
    /// The folder to create in, or the entry to rename.
    pub path: String,
    /// The new folder's name, or the entry's new name. One path component.
    pub name: String,
}

#[tauri::command]
pub async fn sftp_home(state: State<'_, AppState>, webview: Webview, request: SftpTokenRequest) -> CmdResult<String> {
    let sftp = session_for(&state, &webview, &request.token).await?;
    sftp.canonicalize(".").await.map_err(|e| CommandError::from(format!("sftp: {e}")))
}

#[tauri::command]
pub async fn sftp_list(state: State<'_, AppState>, webview: Webview, request: SftpPathRequest) -> CmdResult<Listing> {
    let sftp = session_for(&state, &webview, &request.token).await?;
    sftp_session::remote_list(&sftp, &request.path).await.map_err(CommandError::from)
}

#[tauri::command]
pub async fn sftp_mkdir(state: State<'_, AppState>, webview: Webview, request: SftpNameRequest) -> CmdResult<String> {
    let sftp = session_for(&state, &webview, &request.token).await?;
    let path = sftp_session::remote_mkdir(&sftp, &request.path, &request.name).await.map_err(CommandError::from)?;
    log::info!(target: "audit", "sftp.mkdir: token={} path={}", request.token, path.escape_debug());
    Ok(path)
}

#[tauri::command]
pub async fn sftp_rename(state: State<'_, AppState>, webview: Webview, request: SftpNameRequest) -> CmdResult<String> {
    let sftp = session_for(&state, &webview, &request.token).await?;
    let path = sftp_session::remote_rename(&sftp, &request.path, &request.name).await.map_err(CommandError::from)?;
    log::info!(
        target: "audit",
        "sftp.rename: token={} from={} to={}",
        request.token,
        request.path.escape_debug(),
        path.escape_debug()
    );
    Ok(path)
}

#[tauri::command]
pub async fn sftp_remove(state: State<'_, AppState>, webview: Webview, request: SftpPathRequest) -> CmdResult<()> {
    let sftp = session_for(&state, &webview, &request.token).await?;
    let result = sftp_session::remote_remove(&sftp, &request.path).await;
    log::info!(
        target: "audit",
        "sftp.remove: token={} path={} outcome={}",
        request.token,
        request.path.escape_debug(),
        if result.is_ok() { "ok" } else { "failed" }
    );
    result.map_err(CommandError::from)
}

#[derive(Deserialize)]
pub struct SftpTransferRequest {
    pub token: String,
    /// Chosen by the window; names the progress events and the cancel.
    pub transfer_id: String,
    pub direction: Direction,
    /// Absolute paths on the source side (local for an upload).
    pub sources: Vec<String>,
    /// The folder on the destination side the sources are copied into.
    pub dest_dir: String,
    /// Replace existing destinations. The window sets it only after the
    /// operator confirmed an `exists:` refusal.
    #[serde(default)]
    pub overwrite: bool,
}

fn transfer_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Copy files and folders between the two panes. Resolves when the transfer
/// ends; progress arrives on `sftp-progress-<token>` meanwhile.
#[tauri::command]
pub async fn sftp_transfer(
    state: State<'_, AppState>,
    app: AppHandle,
    webview: Webview,
    request: SftpTransferRequest,
) -> CmdResult<TransferOutcome> {
    if !transfer_id_ok(&request.transfer_id) {
        return Err(CommandError::from("sftp: invalid transfer id".to_string()));
    }
    require_session_window(&state, &webview, &request.token).await?;
    let (sftp, transfers) = match state.connect_sessions.lock().await.get(&request.token) {
        Some(SessionState::Sftp(s)) => (Arc::clone(&s.sftp), Arc::clone(&s.transfers)),
        Some(_) => return Err(CommandError::from(format!("session `{}` is not an SFTP session", request.token))),
        None => return Err(CommandError::from("the SFTP session has ended".to_string())),
    };
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut map = transfers.lock().map_err(|_| CommandError::from("sftp: transfer registry poisoned".to_string()))?;
        if map.contains_key(&request.transfer_id) {
            return Err(CommandError::from("sftp: a transfer with this id is already running".to_string()));
        }
        map.insert(request.transfer_id.clone(), Arc::clone(&cancel));
    }
    let events = crate::session::routing::SessionEvents::new(app, request.token.clone());
    let progress_event = sftp_session::progress_event_name(&request.token);
    let sources_for_audit = request.sources.iter().map(|s| s.escape_debug().to_string()).collect::<Vec<_>>().join(",");
    let outcome = sftp_session::run_transfer(
        sftp,
        cancel,
        events,
        progress_event,
        TransferRequest {
            transfer_id: request.transfer_id.clone(),
            direction: request.direction,
            sources: request.sources,
            dest_dir: request.dest_dir.clone(),
            overwrite: request.overwrite,
        },
    )
    .await;
    if let Ok(mut map) = transfers.lock() {
        map.remove(&request.transfer_id);
    }
    // Paths, counts and the outcome — never file contents.
    log::info!(
        target: "audit",
        "sftp.transfer: token={} direction={} sources=[{}] dest={} overwrite={} outcome={} files={} bytes={} \
         skipped={}{}",
        request.token,
        request.direction.as_str(),
        sources_for_audit,
        request.dest_dir.escape_debug(),
        request.overwrite,
        outcome.outcome,
        outcome.files,
        outcome.bytes,
        outcome.skipped,
        outcome.error.as_deref().map(|e| format!(" error={}", e.escape_debug())).unwrap_or_default(),
    );
    Ok(outcome)
}

#[derive(Deserialize)]
pub struct SftpCancelRequest {
    pub token: String,
    pub transfer_id: String,
}

#[tauri::command]
pub async fn sftp_cancel_transfer(
    state: State<'_, AppState>,
    webview: Webview,
    request: SftpCancelRequest,
) -> CmdResult<()> {
    require_session_window(&state, &webview, &request.token).await?;
    if let Some(SessionState::Sftp(s)) = state.connect_sessions.lock().await.get(&request.token) {
        if let Ok(map) = s.transfers.lock() {
            if let Some(flag) = map.get(&request.transfer_id) {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
    Ok(())
}

/// The operator's home folder on this machine, the local pane's start.
#[tauri::command]
pub async fn sftp_local_home(
    state: State<'_, AppState>,
    webview: Webview,
    request: SftpTokenRequest,
) -> CmdResult<String> {
    session_for(&state, &webview, &request.token).await?;
    dirs::home_dir()
        .map(|p| p.display().to_string())
        .ok_or_else(|| CommandError::from("the home folder of this account is unknown".to_string()))
}

#[tauri::command]
pub async fn sftp_local_list(
    state: State<'_, AppState>,
    webview: Webview,
    request: SftpPathRequest,
) -> CmdResult<Listing> {
    session_for(&state, &webview, &request.token).await?;
    sftp_session::local_list(&request.path).await.map_err(CommandError::from)
}

#[tauri::command]
pub async fn sftp_local_mkdir(
    state: State<'_, AppState>,
    webview: Webview,
    request: SftpNameRequest,
) -> CmdResult<String> {
    session_for(&state, &webview, &request.token).await?;
    sftp_session::local_mkdir(&request.path, &request.name).await.map_err(CommandError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session the policy wants brokered is refused, never dialled
    /// direct (features/sftp-connect.md, "Transport").
    #[test]
    fn a_brokered_transport_is_refused_not_downgraded() {
        let bastions = vec!["b1".to_string()];
        assert!(transport_refusal("rustion-required", &[]).is_some());
        assert!(transport_refusal("rustion-required", &bastions).is_some());
        assert!(transport_refusal("rustion-preferred", &bastions).is_some());
        // Preferred with nothing to prefer is direct, as for SSH.
        assert!(transport_refusal("rustion-preferred", &[]).is_none());
        assert!(transport_refusal("direct", &bastions).is_none());
        assert!(transport_refusal("", &[]).is_none());
    }

    #[test]
    fn transfer_ids_are_short_and_plain() {
        assert!(transfer_id_ok("tx_01-abc"));
        for bad in ["", "a b", "../x", "x\n", &"a".repeat(65)] {
            assert!(!transfer_id_ok(bad), "{bad:?}");
        }
    }
}
