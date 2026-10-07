//! Session Workspace host commands (features/session-workspace.md, T38):
//! the session-layout preference (Phase 0), the attachment commands, the
//! window-close fan-out and the orphan watchdog (Phase 2), saved layouts
//! (Phase 5) and moving a live session between windows (Phase 6).
//!
//! The window a command acts for is always the *calling* webview, never a
//! label the caller names. A label in the request would let any webview
//! with IPC — a plugin window, another session's window — claim, release
//! or keep alive a session rendered somewhere else.
//!
//! None of these commands opens, resolves or authorises anything: they
//! move a live session's rendering between windows and decide when an
//! orphan is stopped. Every open still goes through `session_open_*`.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State, Webview};

use crate::error::{CmdResult, CommandError};
use crate::preferences::SessionWorkspacePrefs;
use crate::session::attachments::{
    self, may_list_sessions, own_window_label, AttachOutcome, ReapPolicy, SessionListing, WindowState, WATCHDOG_TICK,
};
use crate::session::layouts::{self, LayoutInput, PaneSource, SavedLayout};
use crate::session::workspace::{Placement, WORKSPACE_WINDOW_LABEL};
use crate::session::{workspace, ProfileProtocol, SessionState};
use crate::state::AppState;

use super::connect::{build_own_session_window, ensure_workspace_window, resolve_session_layout, run_cleanup};

// ── Preferences (Phase 0) ─────────────────────────────────────────────

#[tauri::command]
pub async fn get_session_workspace_prefs() -> CmdResult<SessionWorkspacePrefs> {
    Ok(crate::preferences::load().unwrap_or_default().session_workspace)
}

/// Validated before it is written, so the file never carries a value an
/// open would refuse. Loads strictly: a preferences file that does not
/// parse is reported, not overwritten with defaults (which would drop the
/// saved vault list).
#[tauri::command]
pub async fn set_session_workspace_prefs(prefs: SessionWorkspacePrefs) -> CmdResult<()> {
    workspace::validate_prefs(&prefs).map_err(CommandError::from)?;
    let mut all = crate::preferences::load()?;
    all.session_workspace = prefs;
    crate::preferences::save(&all)
}

// ── Attachment commands (Phase 2) ─────────────────────────────────────

/// Every live SSH/RDP session, with the window rendering it. Only the main
/// window and the Session Workspace may ask (see
/// [`attachments::may_list_sessions`]).
#[tauri::command]
pub async fn session_list_open(state: State<'_, AppState>, webview: Webview) -> CmdResult<Vec<SessionListing>> {
    let caller = webview.label().to_string();
    if !may_list_sessions(&caller) {
        log::warn!("resource-connect: session_list_open refused for window `{caller}`");
        return Err(CommandError::from(format!(
            "window `{caller}` may not list sessions; only the main window and the Session Workspace can"
        )));
    }
    // Report only what is live in the session registry right now. The two
    // locks are taken one after the other, never together.
    let live: std::collections::HashSet<String> = state
        .connect_sessions
        .lock()
        .await
        .iter()
        .filter(|(_, s)| matches!(s, SessionState::Ssh(_) | SessionState::Rdp(_)))
        .map(|(t, _)| t.clone())
        .collect();
    let listing = state.session_attachments.lock().await.list();
    Ok(listing.into_iter().filter(|row| live.contains(&row.descriptor.token)).collect())
}

#[derive(Deserialize)]
pub struct SessionTokenRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct SessionAttachResponse {
    /// The calling window's label, now the session's holder.
    pub window_label: String,
    /// Set when the previous holder's window no longer existed.
    pub took_over_from: Option<String>,
}

/// Claim a session for the calling window. Only the session's own window
/// and the Session Workspace may; a session held by another window that
/// still exists is refused.
#[tauri::command]
pub async fn session_attach(
    state: State<'_, AppState>,
    app: AppHandle,
    webview: Webview,
    request: SessionTokenRequest,
) -> CmdResult<SessionAttachResponse> {
    let caller = webview.label().to_string();
    let outcome = state
        .session_attachments
        .lock()
        .await
        .attach(&request.token, &caller, Instant::now(), |label| app.get_webview_window(label).is_some());
    match outcome {
        Ok(AttachOutcome::TookOver { previous }) => {
            log::info!(
                "resource-connect: session {} re-attached to window {caller} (previous window {previous} is gone)",
                request.token
            );
            Ok(SessionAttachResponse { window_label: caller, took_over_from: Some(previous) })
        }
        Ok(_) => Ok(SessionAttachResponse { window_label: caller, took_over_from: None }),
        Err(e) => Err(CommandError::from(e.message(&request.token))),
    }
}

/// Release a session from the calling window without stopping it — the
/// move-between-windows path. A session nothing re-attaches is stopped by
/// the watchdog after `UNATTACHED_GRACE`.
#[tauri::command]
pub async fn session_detach(
    state: State<'_, AppState>,
    webview: Webview,
    request: SessionTokenRequest,
) -> CmdResult<()> {
    let caller = webview.label().to_string();
    state
        .session_attachments
        .lock()
        .await
        .detach(&request.token, &caller, Instant::now())
        .map_err(|e| CommandError::from(e.message(&request.token)))
}

#[derive(Serialize)]
pub struct SessionHeartbeatResponse {
    /// How many sessions the calling window holds.
    pub attached: usize,
}

/// Liveness for the watchdog, from the calling window: one call per window
/// every 15 s, not one per pane.
#[tauri::command]
pub async fn session_heartbeat(state: State<'_, AppState>, webview: Webview) -> CmdResult<SessionHeartbeatResponse> {
    let attached = state.session_attachments.lock().await.heartbeat(webview.label(), Instant::now());
    Ok(SessionHeartbeatResponse { attached })
}

// ── Moving a live session between windows (Phase 6) ─────────────────

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MoveTarget {
    /// The session's own window (`ssh-<token>` / `rdp-<token>`).
    OwnWindow,
    /// The Session Workspace, as a new tab.
    Workspace,
}

#[derive(Deserialize)]
pub struct SessionMoveRequest {
    pub token: String,
    pub to: MoveTarget,
}

#[derive(Serialize)]
pub struct SessionMoveResponse {
    /// The window now holding the session.
    pub window_label: String,
}

/// Move a live session from the calling window to its own window or to
/// the workspace, without stopping it.
///
/// Only the holder may move a session, and only to a window `attach`
/// accepts. The registry hands the session straight to the destination
/// (`AttachmentRegistry::transfer`): no detached gap, input narrowed to
/// exactly one window throughout, and a new holder epoch, so SSH output
/// waits — buffered, see `session::output` — until the destination's pane
/// has its listeners up. An RDP session's frame channel is dropped from the
/// old window at once; the new pane attaches its own and gets a full frame.
///
/// Moving *into* the workspace is refused in the *Separate windows* layout
/// (the operator's isolation choice), exactly as an open would be. A
/// destination window that cannot be built hands the session back.
#[tauri::command]
pub async fn session_move(
    state: State<'_, AppState>,
    app: AppHandle,
    webview: Webview,
    request: SessionMoveRequest,
) -> CmdResult<SessionMoveResponse> {
    let caller = webview.label().to_string();
    let token = request.token.as_str();
    let layout_prefs = match request.to {
        MoveTarget::Workspace => resolve_session_layout(Some(Placement::WorkspaceTab))?.1,
        MoveTarget::OwnWindow => crate::preferences::load().map(|p| p.session_workspace).unwrap_or_default(),
    };
    let descriptor = state
        .session_attachments
        .lock()
        .await
        .descriptor(token)
        .cloned()
        .ok_or_else(|| CommandError::from(format!("session token `{token}` not found")))?;
    let target = match request.to {
        MoveTarget::OwnWindow => own_window_label(descriptor.protocol, token),
        MoveTarget::Workspace => WORKSPACE_WINDOW_LABEL.to_string(),
    };
    if target == caller {
        return Err(CommandError::from(format!("session `{token}` is already rendered by window `{caller}`")));
    }
    if request.to == MoveTarget::OwnWindow && app.get_webview_window(&target).is_some() {
        return Err(CommandError::from(format!(
            "window `{target}` still exists (it may be closing); try again in a moment"
        )));
    }
    state
        .session_attachments
        .lock()
        .await
        .transfer(token, &caller, &target, Instant::now())
        .map_err(|e| CommandError::from(e.message(token)))?;
    if descriptor.protocol == ProfileProtocol::Rdp {
        crate::session::rdp::detach_frames(&state, token).await;
    }

    let built = match request.to {
        MoveTarget::OwnWindow => build_own_session_window(&app, &descriptor, &layout_prefs),
        MoveTarget::Workspace => ensure_workspace_window(&app),
    };
    if let Err(e) = built {
        // Hand it back rather than leave it with a window that will never
        // exist (the watchdog would stop it after `WINDOW_GONE_GRACE`).
        let back = state.session_attachments.lock().await.transfer(token, &target, &caller, Instant::now());
        log::warn!(
            "resource-connect: moving session {token} to window {target} failed ({e}); {}",
            if back.is_ok() { "handed back" } else { "it could not be handed back" }
        );
        return Err(CommandError::from(format!("move session to `{target}`: {e}")));
    }
    if request.to == MoveTarget::Workspace {
        if let Err(e) = app.emit_to(WORKSPACE_WINDOW_LABEL, workspace::PLACED_EVENT, ()) {
            log::warn!("resource-connect: could not notify the session workspace: {e}");
        }
        // The session's own window has nothing left to render. Its close
        // hook stops only what is still attached to it — nothing now.
        if let Some(win) = app.get_webview_window(&caller) {
            if let Err(e) = win.close() {
                log::debug!("resource-connect: could not close window {caller} after a move: {e}");
            }
        }
    }
    log::info!("resource-connect: session {token} moved from window {caller} to window {target}");
    Ok(SessionMoveResponse { window_label: target })
}

/// Open (or raise) the Session Workspace window from the main window, so
/// its empty state — Connect, and Restore last layout — is reachable when
/// no session put it on screen. Refused in the *Separate windows* layout.
#[tauri::command]
pub async fn session_workspace_open(app: AppHandle, webview: Webview) -> CmdResult<()> {
    if webview.label() != "main" {
        return Err(CommandError::from(format!(
            "window `{}` may not open the Session Workspace; only the main window can",
            webview.label()
        )));
    }
    resolve_session_layout(Some(Placement::WorkspaceTab))?;
    ensure_workspace_window(&app).map_err(|e| CommandError::from(format!("session workspace window: {e}")))
}

// ── Saved layouts (Phase 5) ───────────────────────────────────────────

/// Windows that may read or forget the saved layout: the workspace, which
/// restores it, and the main window (Settings).
fn may_read_layouts(caller: &str) -> bool {
    caller == "main" || caller == WORKSPACE_WINDOW_LABEL
}

/// Save the workspace's current layout as its vault's last layout.
///
/// The workspace sends the tree with each leaf naming a live session by
/// token; the host resolves every token against its own registry and
/// writes only `{resource_name, profile_id, protocol}` and the namespace
/// the session was opened in — never the token, a credential or output.
/// A layout with nothing left to save leaves the saved one in place.
#[tauri::command]
pub async fn session_layout_save(
    state: State<'_, AppState>,
    webview: Webview,
    layout: LayoutInput,
) -> CmdResult<SessionLayoutSaveResponse> {
    if webview.label() != WORKSPACE_WINDOW_LABEL {
        return Err(CommandError::from(format!(
            "window `{}` may not save a session layout; only the Session Workspace can",
            webview.label()
        )));
    }
    let built = {
        let registry = state.session_attachments.lock().await;
        layouts::build_saved_layout(
            &layout,
            |token| {
                // Only sessions this window holds are part of its layout.
                if registry.route(token) != attachments::Route::Attached(WORKSPACE_WINDOW_LABEL.to_string()) {
                    return None;
                }
                registry.descriptor(token).map(|d| PaneSource {
                    resource_name: d.resource_name.clone(),
                    profile_id: d.profile_id.clone(),
                    protocol: d.protocol,
                    namespace: d.namespace.clone(),
                    vault_id: d.vault_id.clone(),
                })
            },
            super::connect::now_rfc3339(),
        )
        .map_err(CommandError::from)?
    };
    let Some((vault_id, saved)) = built else {
        return Ok(SessionLayoutSaveResponse { saved_panes: 0 });
    };
    let saved_panes = layouts::panes(&saved).len();
    let path = layouts::layouts_path().map_err(CommandError::from)?;
    layouts::save_at(&path, &vault_id, saved).map_err(CommandError::from)?;
    Ok(SessionLayoutSaveResponse { saved_panes })
}

#[derive(Serialize)]
pub struct SessionLayoutSaveResponse {
    /// Panes written; 0 when nothing was saved.
    pub saved_panes: usize,
}

#[derive(Serialize)]
pub struct SessionLayoutView {
    /// The vault profile the layout belongs to (the open vault).
    pub vault_id: String,
    /// The session's active namespace (`""` = root), for the restore check.
    pub active_namespace: String,
    pub layout: Option<SavedLayout>,
}

/// The open vault's saved layout, if any, with the active namespace. Never
/// restores anything: the workspace re-opens each pane itself, through the
/// normal open path, when the operator asks.
#[tauri::command]
pub async fn session_layout_get(state: State<'_, AppState>, webview: Webview) -> CmdResult<SessionLayoutView> {
    if !may_read_layouts(webview.label()) {
        return Err(CommandError::from(format!("window `{}` may not read saved session layouts", webview.label())));
    }
    let vault_id = crate::embedded::current_vault_id();
    let active_namespace =
        layouts::normalize_namespace(&state.active_namespace.lock().await.clone().unwrap_or_default());
    let path = layouts::layouts_path().map_err(CommandError::from)?;
    let layout = layouts::get_at(&path, &vault_id).map_err(CommandError::from)?;
    Ok(SessionLayoutView { vault_id, active_namespace, layout })
}

/// Forget the open vault's saved layout. Returns whether there was one.
#[tauri::command]
pub async fn session_layout_forget(webview: Webview) -> CmdResult<bool> {
    if !may_read_layouts(webview.label()) {
        return Err(CommandError::from(format!("window `{}` may not forget saved session layouts", webview.label())));
    }
    let path = layouts::layouts_path().map_err(CommandError::from)?;
    layouts::forget_at(&path, &crate::embedded::current_vault_id()).map_err(CommandError::from)
}

// ── Teardown ──────────────────────────────────────────────────────────

/// Why a window's sessions are being stopped.
#[derive(Debug, Clone, Copy)]
pub enum WindowCloseCause {
    /// The operator closed the window (`WindowEvent::CloseRequested`).
    WindowClose,
    /// The window's web content process died (macOS hook).
    RendererTerminated,
}

/// Stop every session attached to `window_label` and run each cleanup
/// hook once. `own_token` is an own window's session — see
/// [`attachments::stop_window_sessions`].
pub(crate) async fn close_window_sessions(
    app: &AppHandle,
    window_label: &str,
    own_token: Option<&str>,
    cause: WindowCloseCause,
) {
    let state = app.state::<AppState>();
    let stopped = attachments::stop_window_sessions(&state, window_label, own_token).await;
    for (token, cleanup) in stopped {
        if let Some(c) = cleanup {
            run_cleanup(&state, c).await;
        }
        match cause {
            WindowCloseCause::WindowClose => {
                log::info!("resource-connect: window-close → session drop {token} (window {window_label})")
            }
            WindowCloseCause::RendererTerminated => log::warn!(
                target: "audit",
                "session.reaped: token={token} window={window_label} reason=renderer_terminated"
            ),
        }
    }
}

// ── Watchdog (Phase 2) ────────────────────────────────────────────────

/// Start the orphan watchdog. Called once from the Tauri `setup` hook.
pub(crate) fn spawn_watchdog(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let policy = ReapPolicy::for_this_platform();
        let mut tick = tokio::time::interval(WATCHDOG_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `interval` fires immediately; skip that so the first judgement
        // is a full tick after start-up.
        tick.tick().await;
        loop {
            tick.tick().await;
            reap_orphans(&app, policy).await;
        }
    });
}

/// One watchdog tick: snapshot the windows that hold sessions, take every
/// orphan out of the registry under its lock, then stop each through the
/// same path as a clean close.
async fn reap_orphans(app: &AppHandle, policy: ReapPolicy) {
    let state = app.state::<AppState>();
    let labels = state.session_attachments.lock().await.window_labels();
    // Window lookups happen outside the registry lock: visibility and
    // minimised state are answered by the main thread.
    let windows: HashMap<String, WindowState> = labels
        .into_iter()
        .map(|label| {
            let window = window_state(app, &label, policy);
            (label, window)
        })
        .collect();
    let reaped = state.session_attachments.lock().await.reap(Instant::now(), &windows, policy);
    for r in reaped {
        log::warn!(
            target: "audit",
            "session.reaped: token={} window={} reason={} idle_secs={}",
            r.token,
            r.window_label.as_deref().unwrap_or("-"),
            r.reason.as_str(),
            r.idle.as_secs(),
        );
        if let Some(c) = attachments::stop_session(&state, &r.token).await {
            run_cleanup(&state, c).await;
        }
    }
}

fn window_state(app: &AppHandle, label: &str, policy: ReapPolicy) -> WindowState {
    let Some(window) = app.get_webview_window(label) else {
        return WindowState::Missing;
    };
    if !policy.judge_heartbeats {
        // Staleness is not judged on this platform; spare the main-thread
        // round trips. Any present window reads as not judgeable.
        return WindowState::Hidden;
    }
    match (window.is_visible(), window.is_minimized()) {
        (Ok(true), Ok(false)) => WindowState::Shown,
        // Hidden, minimised, or the window is going away mid-query: not
        // proof of a dead renderer.
        _ => WindowState::Hidden,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::session::workspace::WORKSPACE_WINDOW_LABEL;

    fn capability_windows(file: &str) -> Vec<String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities").join(file);
        let cap: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        cap["windows"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
    }

    /// The workspace window needs IPC (its session commands, events, its
    /// own close) and gets it from its own capability, by exact label — not
    /// by a glob that could also match a label a plugin or web window could
    /// take — and not from the default capability, which carries every app
    /// command (T110; what that capability grants is checked in
    /// `window_acl_tests`). (`capability_isolation_tests` in `connect_web.rs`
    /// keeps every capability away from web session windows.)
    #[test]
    fn the_workspace_capability_names_the_workspace_window_exactly() {
        assert_eq!(capability_windows("session-workspace.json"), [WORKSPACE_WINDOW_LABEL]);
        let default = capability_windows("default.json");
        for pattern in &default {
            assert!(!pattern.starts_with("session-"), "default.json reaches the workspace: {pattern}");
        }
    }
}
