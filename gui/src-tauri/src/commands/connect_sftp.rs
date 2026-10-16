//! Tauri commands for SFTP connection profiles (features/sftp-connect.md).
//!
//! `session_open_sftp` reuses the SSH open path's building blocks — profile
//! lookup, connect-time MFA, `resolve_ssh_credential` (and with it the SSH
//! login-class rule), host candidates, host-key pinning, and the Rustion
//! route (T141) — and differs in two ways:
//!
//! * **No `provider` source.** `connect/authorize` releases provider
//!   accounts for ssh / rdp / web only.
//! * **Always its own window** (`sftp-<token>`), never a workspace pane.
//!
//! **Brokered transport.** When the effective Rustion policy routes the
//! resource through a bastion, the session goes the way an SSH session does:
//! an SSH ticket from `rustion/v2/session/open` (server-resolved sources) or
//! `rustion/session/open` (client-resolved ones), the operator's client
//! authenticates to the bastion as `operator` with the ticket and pins the
//! *bastion's* host key, then asks for the `sftp` subsystem, which the
//! bastion relays to the target (Rustion ≥ 0.17.0, its M39). The ticket is an
//! ordinary `ssh` ticket — Rustion has no separate SFTP ticket protocol. A
//! credential the bastion cannot use is refused under `rustion-required` and
//! dialled direct under `rustion-preferred`, exactly as for SSH; it is never
//! silently dialled direct under `rustion-required`.
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

use zeroize::Zeroizing;

use super::connect::{
    collect_policy_hints, find_profile, is_connect_layer_error, open_context, open_rustion_session_v2_ssh, profile_host_candidates,
    profile_port, profile_username, read_effective_policy, read_resource_meta, record_recent_session, require_session_window,
    resolve_session_layout, resolve_ssh_connect_route, resolve_ssh_credential, spawn_own_session_window,
    now_rfc3339, ConnectRoute, OperatorCredential, SessionProtocolTag,
};
use super::connect_provider::{dial_in_order, DialFailure};
use crate::error::{CmdResult, CommandError};
use crate::session::{
    self,
    attachments::SessionDescriptor,
    sftp::{self as sftp_session, Direction, Listing, SftpOpenArgs, SftpOpenOutcome, TransferOutcome, TransferRequest},
    ssh::{SshCredential, CONNECT_TIMEOUT},
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

/// Credential sources `rustion/v2/session/open` resolves server-side for an
/// SSH ticket. Every other source resolves on this machine first and is
/// handed to `rustion/session/open` (or dialled direct). `provider` is not
/// here: an SFTP profile refuses it before any route is chosen.
fn resolves_server_side(credential_source_kind: &str) -> bool {
    matches!(credential_source_kind, "secret" | "ssh-engine" | "default-account")
}

/// Where the SFTP connection is dialled and how it authenticates.
struct DialInputs {
    hosts: Vec<String>,
    port: u16,
    username: String,
    credential: SshCredential,
    /// `SHA256:<base64>`; empty = trust on first use (logged).
    host_key_fingerprint: String,
    /// The bastion's name when the route goes through one.
    bastion_name: Option<String>,
}

/// The dial for a chosen route. On a bastion route nothing of the target is
/// used: the bastion is the only host, the login is `operator` with the
/// one-shot ticket as the password, and the pin is the bastion's own host
/// key (the profile's `host_key_pin` names the target's key, which the
/// bastion checks on its side). The target credential, if one was resolved
/// here, has already been sealed into the ticket and is not presented.
fn dial_inputs(
    route: &ConnectRoute,
    direct_hosts: Vec<String>,
    direct_port: u16,
    direct_username: &str,
    direct_credential: Option<SshCredential>,
    target_host_key_pin: &str,
) -> Result<DialInputs, String> {
    match route {
        ConnectRoute::Direct => Ok(DialInputs {
            hosts: direct_hosts,
            port: direct_port,
            username: direct_username.to_string(),
            credential: direct_credential.ok_or_else(|| "direct dial requires a resolved credential".to_string())?,
            host_key_fingerprint: target_host_key_pin.to_string(),
            bastion_name: None,
        }),
        ConnectRoute::Rustion { bastion_host, bastion_port, ticket, bastion_name, bastion_pin, .. } => Ok(DialInputs {
            hosts: vec![bastion_host.clone()],
            port: *bastion_port,
            username: "operator".to_string(),
            credential: SshCredential::Password(Zeroizing::new(ticket.clone())),
            host_key_fingerprint: bastion_pin.clone(),
            bastion_name: Some(bastion_name.clone()),
        }),
    }
}

/// Add the likely cause to an SFTP start failure through a bastion: a
/// Rustion older than 0.17.0 acknowledges the `sftp` subsystem without
/// relaying it, so the SFTP handshake never completes and the open times
/// out. The connect timeout is therefore hinted too (it can also be an
/// unreachable bastion, which the message says); authentication and other
/// failures are left as they are.
fn explain_bastion_sftp_failure(bastion: &str, message: String) -> String {
    if message.starts_with("sftp:") {
        format!(
            "{message} (through Rustion bastion `{bastion}`: either the bastion is unreachable, or it predates \
             Rustion 0.17.0, the first release that relays the `sftp` subsystem for ticket sessions)"
        )
    } else {
        message
    }
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
    // What the bastion dials after consuming the ticket, as for SSH.
    let primary_target_host = host_candidates.first().cloned().unwrap_or_default();
    let profile_user = profile_username(&profile);

    // Server-resolved sources first: when the policy routes through a
    // bastion, `rustion/v2/session/open` evaluates the profile's MFA gate,
    // burns the ticket and seals the credential into the envelope — nothing
    // is resolved here. `Direct` means the policy did not pick a bastion
    // (a lock violation has already been refused inside).
    let credential_source = profile.get("credential_source").cloned().unwrap_or(Value::Null);
    let v2_route = if resolves_server_side(kind) {
        match open_rustion_session_v2_ssh(
            &state,
            &request.resource_name,
            &request.profile_id,
            request.connect_ticket.as_deref(),
            &meta,
            &profile,
            &primary_target_host,
            port,
            &profile_user,
            &credential_source,
            None,
        )
        .await?
        {
            r @ ConnectRoute::Rustion { .. } => Some(r),
            ConnectRoute::Direct => None,
        }
    } else {
        None
    };

    // `session_audit` is set on the client-side path only; the bastion path
    // has the login class and mint stamped server-side.
    let (route, credential, username, on_close, session_audit) = if let Some(r) = v2_route {
        (r, None, profile_user.clone(), None, None)
    } else {
        // A lock violation is refused before the MFA ticket is burnt or a
        // credential resolved (an LDAP library check-out would otherwise be
        // left checked out: its cleanup only runs with a session). The route
        // resolution below re-reads the policy and stays authoritative.
        let (resource_id, resource_type, asset_group_ids) =
            collect_policy_hints(&state, &request.resource_name, &meta).await;
        let effective = read_effective_policy(&state, &resource_id, &resource_type, &asset_group_ids).await?;
        if let Some(detail) = &effective.lock_violation {
            return Err(CommandError::from(format!("rustion policy lock violation: {detail}")));
        }
        // Connect-time MFA: the ticket is redeemed before any credential is
        // resolved or minted, exactly as on the SSH client-side path.
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
        let username = resolved.effective_username.clone().unwrap_or_else(|| profile_user.clone());
        if username.is_empty() {
            return Err(CommandError::from(
                "SFTP profile has no username (set profile.username, use a `default-account` or LDAP credential \
                 source, or give the ssh-engine role a `default_user`)"
                    .to_string(),
            ));
        }
        // Lock violation, transport tier and brokerability of this
        // credential, as for SSH: brokered under a bastion policy, refused
        // under `rustion-required` when the bastion cannot use it.
        let route = resolve_ssh_connect_route(
            &state,
            &request.resource_name,
            &meta,
            &profile,
            &primary_target_host,
            port,
            &username,
            &resolved.credential,
        )
        .await?;
        let engine_mint = resolved.engine_mint;
        (route, Some(resolved.credential), username, resolved.on_close, Some((login_class, engine_mint)))
    };

    let dial = dial_inputs(&route, host_candidates, port, &username, credential, &host_key_fingerprint)
        .map_err(CommandError::from)?;
    if let Some(bastion) = &dial.bastion_name {
        if dial.host_key_fingerprint.is_empty() {
            log::warn!(
                "resource-connect/sftp: bastion `{bastion}` advertised no host-key fingerprint — dialling unpinned \
                 (TOFU). Run `rustion_target_refresh_listeners` against a Rustion ≥ listener-schema-v2 to enable \
                 pinning."
            );
        }
        log::info!(
            "resource-connect/sftp: routing through Rustion bastion `{bastion}` ({}:{}) host-key-pin={}",
            dial.hosts.first().map(String::as_str).unwrap_or(""),
            dial.port,
            if dial.host_key_fingerprint.is_empty() { "none" } else { dial.host_key_fingerprint.as_str() }
        );
    }

    let dial_port = dial.port;
    let (host, outcome): (String, SftpOpenOutcome) = dial_in_order("sftp", &dial.hosts, dial_port, |host| {
        let app = app.clone();
        let state = &state;
        let args = SftpOpenArgs {
            host: host.clone(),
            port: dial_port,
            username: dial.username.clone(),
            credential: dial.credential.clone(),
            host_key_fingerprint: dial.host_key_fingerprint.clone(),
            label: format!("sftp {}@{host}:{dial_port}", dial.username),
            on_close: on_close.clone(),
        };
        let bastion = dial.bastion_name.clone();
        async move {
            let explain = |m: String| match &bastion {
                Some(b) => explain_bastion_sftp_failure(b, m),
                None => m,
            };
            match tokio::time::timeout(CONNECT_TIMEOUT, sftp_session::open_sftp_session(app, state, args)).await {
                Ok(Ok(o)) => Ok(o),
                Ok(Err(e)) => Err(DialFailure { network_layer: is_connect_layer_error(&e), message: explain(e) }),
                Err(_) => Err(DialFailure {
                    message: explain(format!(
                        "sftp: connect+auth to {host}:{dial_port} timed out after {}s",
                        CONNECT_TIMEOUT.as_secs()
                    )),
                    network_layer: true,
                }),
            }
        }
    })
    .await?;
    let label = match &dial.bastion_name {
        Some(bastion) => format!("sftp {username}@{primary_target_host}:{port} via rustion[{bastion}]"),
        None => format!("sftp {username}@{host}:{port}"),
    };

    match (&route, &session_audit) {
        (ConnectRoute::Rustion { bastion_name, session_id, correlation_id, .. }, audit) => {
            // On the v2 path (`audit` is `None`) the control plane stamps
            // login class, mint and cert serial on its own row; on the
            // client-side path they were resolved here and are logged too.
            // Either way the line joins the bastion session to the local
            // token and records that the channel is SFTP.
            let resolved = match audit {
                Some((lc, mint)) => format!(
                    " login_class={} login_class_source={} ssh_engine_mode={} cert_serial={} login_class_chain=[{}]",
                    lc.login_class,
                    lc.login_class_source,
                    mint.as_ref().map(|m| m.mode.as_str()).unwrap_or(""),
                    mint.as_ref().and_then(|m| m.cert_serial.as_deref()).unwrap_or(""),
                    lc.login_class_chain.join(","),
                ),
                None => String::new(),
            };
            log::info!(
                target: "audit",
                "session.open: resource={} protocol=sftp transport=rustion bastion={} rustion_session={} \
                 correlation_id={} token={} target={}:{}{}",
                request.resource_name,
                bastion_name,
                session_id,
                correlation_id,
                outcome.token,
                primary_target_host,
                port,
                resolved,
            );
        }
        (ConnectRoute::Direct, Some((login_class, engine_mint))) => {
            let (mode, serial) = match engine_mint {
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
        }
        // A direct route always comes from the client-side path, which
        // resolved the login class.
        (ConnectRoute::Direct, None) => {}
    }

    // The bastion-side lifecycle (renew, kill), keyed by the local token as
    // for SSH and RDP; the window's Rustion chip reads it, and the drop path
    // removes it.
    if let ConnectRoute::Rustion { bastion_id, bastion_name, session_id, correlation_id, expires_at, max_renewals, .. } =
        &route
    {
        state.rustion_session_bundles.lock().await.insert(
            outcome.token.clone(),
            crate::state::RustionSessionBundle {
                session_id: session_id.clone(),
                bastion_id: bastion_id.clone(),
                bastion_name: bastion_name.clone(),
                correlation_id: correlation_id.clone(),
                expires_at: expires_at.clone(),
                max_renewals: *max_renewals,
                protocol: "sftp".to_string(),
            },
        );
    }

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

    fn rustion_route(pin: &str) -> ConnectRoute {
        ConnectRoute::Rustion {
            bastion_host: "bastion.example.com".to_string(),
            bastion_port: 2222,
            ticket: "tkt_0123456789abcdef0123456789abcdef".to_string(),
            bastion_name: "edge-1".to_string(),
            bastion_id: "b1".to_string(),
            session_id: "s1".to_string(),
            correlation_id: "c1".to_string(),
            expires_at: String::new(),
            max_renewals: 3,
            bastion_pin: pin.to_string(),
        }
    }

    fn target_password() -> Option<SshCredential> {
        Some(SshCredential::Password(Zeroizing::new("target-secret".to_string())))
    }

    /// Through a bastion, nothing of the target reaches the dial: one host
    /// (the bastion), user `operator`, the ticket as the password, and the
    /// bastion's pin — never the target's (T141).
    #[test]
    fn a_bastion_route_dials_the_bastion_with_the_ticket_only() {
        let dial = dial_inputs(
            &rustion_route("SHA256:bastionkey"),
            vec!["10.0.0.5".to_string(), "srv.example.com".to_string()],
            22,
            "deploy",
            target_password(),
            "SHA256:targetkey",
        )
        .unwrap();
        assert_eq!(dial.hosts, vec!["bastion.example.com".to_string()]);
        assert_eq!(dial.port, 2222);
        assert_eq!(dial.username, "operator");
        assert_eq!(dial.host_key_fingerprint, "SHA256:bastionkey");
        assert_eq!(dial.bastion_name.as_deref(), Some("edge-1"));
        match dial.credential {
            SshCredential::Password(p) => assert_eq!(p.as_str(), "tkt_0123456789abcdef0123456789abcdef"),
            _ => panic!("a bastion dial presents the ticket as a password"),
        }
    }

    /// An unpinned bastion stays unpinned (TOFU, logged) rather than
    /// borrowing the target's pin, which names a different key.
    #[test]
    fn a_bastion_without_a_pin_does_not_take_the_targets_pin() {
        let dial = dial_inputs(&rustion_route(""), vec!["h".to_string()], 22, "u", None, "SHA256:targetkey").unwrap();
        assert_eq!(dial.host_key_fingerprint, "");
    }

    /// The server-resolved bastion path resolves no credential locally.
    #[test]
    fn a_bastion_route_needs_no_local_credential() {
        assert!(dial_inputs(&rustion_route("p"), vec!["h".to_string()], 22, "u", None, "").is_ok());
    }

    #[test]
    fn a_direct_route_dials_the_target_with_its_pin_and_credential() {
        let hosts = vec!["10.0.0.5".to_string(), "srv.example.com".to_string()];
        let dial =
            dial_inputs(&ConnectRoute::Direct, hosts.clone(), 2200, "deploy", target_password(), "SHA256:targetkey")
                .unwrap();
        assert_eq!(dial.hosts, hosts);
        assert_eq!(dial.port, 2200);
        assert_eq!(dial.username, "deploy");
        assert_eq!(dial.host_key_fingerprint, "SHA256:targetkey");
        assert!(dial.bastion_name.is_none());
        assert!(matches!(dial.credential, SshCredential::Password(_)));
    }

    /// A direct dial with nothing resolved fails; it never proceeds
    /// without a credential.
    #[test]
    fn a_direct_route_without_a_credential_is_refused() {
        assert!(dial_inputs(&ConnectRoute::Direct, vec!["h".to_string()], 22, "u", None, "").is_err());
    }

    /// The sources `rustion/v2/session/open` resolves; everything else is
    /// resolved here first (and `provider` is refused before routing).
    #[test]
    fn server_side_sources_are_the_v2_set() {
        for k in ["secret", "ssh-engine", "default-account"] {
            assert!(resolves_server_side(k), "{k}");
        }
        for k in ["ldap", "pki", "fido2", "provider", ""] {
            assert!(!resolves_server_side(k), "{k}");
        }
    }

    /// A pre-0.17 bastion acknowledges `sftp` without relaying it; the
    /// handshake failure says so. Auth and network errors are unchanged.
    #[test]
    fn an_sftp_start_failure_through_a_bastion_names_the_minimum_version() {
        let m = explain_bastion_sftp_failure("edge-1", "sftp: the server did not start an SFTP session: x".into());
        assert!(m.contains("Rustion 0.17.0") && m.contains("edge-1") && m.contains("unreachable"), "{m}");
        let auth = "ssh: authentication failed".to_string();
        assert_eq!(explain_bastion_sftp_failure("edge-1", auth.clone()), auth);
    }

    #[test]
    fn transfer_ids_are_short_and_plain() {
        assert!(transfer_id_ok("tx_01-abc"));
        for bad in ["", "a b", "../x", "x\n", &"a".repeat(65)] {
            assert!(!transfer_id_ok(bad), "{bad:?}");
        }
    }
}
