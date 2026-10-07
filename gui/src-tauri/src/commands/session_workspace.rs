//! Session Workspace host commands (features/session-workspace.md, T38):
//! the session-layout preference (Phase 0), the attachment commands, the
//! window-close fan-out and the orphan watchdog (Phase 2), saved layouts
//! (Phase 5), moving a live session between windows (Phase 6), and the
//! native-close protocol that lets a session window ask before it closes
//! (T108, §8).
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State, Webview};
use tokio::sync::Notify;

use crate::error::{CmdResult, CommandError};
use crate::preferences::SessionWorkspacePrefs;
use crate::session::attachments::{
    self, may_list_sessions, own_window_label, AttachOutcome, ReapPolicy, SessionListing, WindowState, WATCHDOG_TICK,
};
use crate::session::close_guard::{renders_sessions, CloseGuard, CloseRequest, CLOSE_ANSWER_TIMEOUT};
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
        // The session's own window has nothing left to render. Destroyed,
        // not closed: a close would go to its page, which asks before it
        // closes a window with a live session (T108) — and the session is
        // no longer that window's. Its `Destroyed` hook stops only what is
        // still attached to it — nothing now.
        if let Some(win) = app.get_webview_window(&caller) {
            if let Err(e) = win.destroy() {
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

// ── Native window close (T108) ────────────────────────────────────────
//
// A window that renders sessions stops them when it is *destroyed*, not
// when the operator asks to close it: its page vetoes the native close
// and asks first (`gui/src/lib/sessionWindowClose.ts`). `session::
// close_guard` is the escape hatch for a page that cannot answer.

fn close_guard(state: &AppState) -> std::sync::MutexGuard<'_, CloseGuard> {
    // Plain bookkeeping, written in one step per call: a panic elsewhere
    // while it was locked leaves nothing half-written, and a poisoned
    // lock must not stop a window from closing.
    state.session_close_guard.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The calling webview, when it is the main webview of a window that
/// renders sessions. The close commands act on that window and no other.
fn calling_session_window(webview: &Webview) -> CmdResult<String> {
    let label = webview.label().to_string();
    if !renders_sessions(&label) || webview.window().label() != label {
        log::warn!("resource-connect: session window close command refused for window `{label}`");
        return Err(CommandError::from(format!(
            "window `{label}` does not render sessions; only a session window or the Session Workspace closes this way"
        )));
    }
    Ok(label)
}

/// The calling window's page has its close request and is asking the
/// operator: its confirmation is on screen. Cancels the forced close the
/// request armed. Answers for the calling window only.
#[tauri::command]
pub async fn session_window_closing(state: State<'_, AppState>, webview: Webview) -> CmdResult<()> {
    let label = calling_session_window(&webview)?;
    let was_pending = close_guard(&state).answered(&label);
    if !was_pending {
        // Late (the close was already forced) or unprompted; either way
        // there is nothing to cancel.
        log::debug!("resource-connect: window {label} answered a close request that was not pending");
    }
    Ok(())
}

/// Close the calling window: the operator confirmed, or nothing in it is
/// live. The host destroys the window, and its `Destroyed` hook stops
/// every session still attached to it — the same stop path as every other
/// exit. Never another window: the window is the caller, not a label in
/// the request (a `core:window:allow-destroy` grant would let the page
/// destroy any window by label).
#[tauri::command]
pub async fn session_window_close(state: State<'_, AppState>, webview: Webview) -> CmdResult<()> {
    let label = calling_session_window(&webview)?;
    close_guard(&state).answered(&label);
    log::info!("resource-connect: closing window {label} at its page's request");
    webview.window().destroy().map_err(|e| CommandError::from(format!("close window `{label}`: {e}")))
}

/// Install the close protocol on a window that renders sessions (its own
/// window, or the workspace). `own_token` is an own window's session, the
/// fail-safe [`attachments::stop_window_sessions`] describes.
///
/// * `CloseRequested` — Tauri has already vetoed the close if the page
///   listens for it. Record the request and arm the escape hatch: if the
///   page has not answered within [`CLOSE_ANSWER_TIMEOUT`], the window's
///   sessions are stopped and the window destroyed. A close the page does
///   not veto goes straight on to `Destroyed`, and the armed timer finds
///   the request forgotten.
/// * `Destroyed` — the window is gone, however it went: stop every session
///   still attached to it.
pub(crate) fn hook_session_window_close(app: &AppHandle, win: &tauri::WebviewWindow, own_token: Option<String>) {
    let app = app.clone();
    let label = win.label().to_string();
    win.on_window_event(move |event| match event {
        tauri::WindowEvent::CloseRequested { .. } => arm_close_escape_hatch(&app, &label, own_token.clone()),
        tauri::WindowEvent::Destroyed => {
            close_guard(&app.state::<AppState>()).forget(&label);
            let app = app.clone();
            let label = label.clone();
            let own_token = own_token.clone();
            tauri::async_runtime::spawn(async move {
                close_window_sessions(&app, &label, own_token.as_deref(), WindowCloseCause::WindowDestroyed).await;
            });
        }
        _ => {}
    });
}

/// A window's web content process died (the macOS hook): stop its
/// sessions now, and — for a window that renders sessions — mark it so its
/// next close request is forced at once. Its page's close listener is still
/// registered with Tauri, so that close is vetoed with nothing left to
/// answer it.
#[cfg(target_os = "macos")]
pub(crate) fn renderer_terminated(app: &AppHandle, label: &str) {
    if renders_sessions(label) {
        close_guard(&app.state::<AppState>()).renderer_gone(label);
    }
    let app = app.clone();
    let label = label.to_string();
    tauri::async_runtime::spawn(async move {
        close_window_sessions(&app, &label, None, WindowCloseCause::RendererTerminated).await;
    });
}

/// Record a close request synchronously — before the page can answer it,
/// since the answer arrives as IPC on the thread this hook runs on — and
/// force the close if it goes unanswered.
fn arm_close_escape_hatch(app: &AppHandle, label: &str, own_token: Option<String>) {
    let request = close_guard(&app.state::<AppState>()).requested(label, Instant::now());
    let app = app.clone();
    let label = label.to_string();
    tauri::async_runtime::spawn(async move {
        let (cause, waited) = match request {
            CloseRequest::ForceNow => (WindowCloseCause::RendererTerminated, Duration::ZERO),
            CloseRequest::AwaitAnswer { id } => {
                tokio::time::sleep(CLOSE_ANSWER_TIMEOUT).await;
                let unanswered = close_guard(&app.state::<AppState>()).take_unanswered(&label, id, Instant::now());
                match unanswered {
                    Some(waited) => (WindowCloseCause::CloseUnanswered, waited),
                    None => return,
                }
            }
        };
        force_close_window(&app, &label, own_token.as_deref(), cause, waited).await;
    });
}

/// The escape hatch fired: the window's page did not answer its close
/// request, or its renderer is known dead. Stop the window's sessions
/// first — the operator asked for the window to go and nothing in it can
/// confirm — then destroy it; its `Destroyed` hook finds nothing left. If
/// the window cannot be destroyed, its sessions are stopped all the same.
async fn force_close_window(
    app: &AppHandle,
    label: &str,
    own_token: Option<&str>,
    cause: WindowCloseCause,
    waited: Duration,
) {
    log::warn!(
        target: "audit",
        "session.window_force_closed: window={label} reason={} waited_ms={}",
        cause.as_str(),
        waited.as_millis()
    );
    close_window_sessions(app, label, own_token, cause).await;
    match app.get_webview_window(label) {
        Some(win) => {
            if let Err(e) = win.destroy() {
                log::warn!(
                    "resource-connect: window {label} could not be destroyed after an unanswered close ({e}); its \
                     sessions are stopped"
                );
            }
        }
        None => log::debug!("resource-connect: window {label} was already gone when its close was forced"),
    }
}

// ── Teardown ──────────────────────────────────────────────────────────

/// Why a window's sessions are being stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowCloseCause {
    /// The window is gone (`WindowEvent::Destroyed`): closed after its
    /// page confirmed, closed with nothing live, or closed by the host.
    WindowDestroyed,
    /// The window's web content process died (macOS hook), or a close was
    /// requested of a window whose renderer is known dead.
    RendererTerminated,
    /// The window's page did not answer a close request in time (T108).
    CloseUnanswered,
}

impl WindowCloseCause {
    fn as_str(self) -> &'static str {
        match self {
            Self::WindowDestroyed => "window_destroyed",
            Self::RendererTerminated => "renderer_terminated",
            Self::CloseUnanswered => "close_unanswered",
        }
    }
}

/// Window teardowns started and not yet finished, so app exit can let them
/// run their cleanups ([`stop_sessions_on_exit`]).
static TEARDOWNS_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static TEARDOWNS_IDLE: Notify = Notify::const_new();

struct InFlightTeardown;

impl InFlightTeardown {
    fn begin() -> Self {
        TEARDOWNS_IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for InFlightTeardown {
    fn drop(&mut self) {
        if TEARDOWNS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst) == 1 {
            TEARDOWNS_IDLE.notify_waiters();
        }
    }
}

async fn wait_for_teardowns() {
    loop {
        let idle = TEARDOWNS_IDLE.notified();
        tokio::pin!(idle);
        idle.as_mut().enable();
        if TEARDOWNS_IN_FLIGHT.load(Ordering::SeqCst) == 0 {
            return;
        }
        idle.await;
    }
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
    let _in_flight = InFlightTeardown::begin();
    let state = app.state::<AppState>();
    let stopped = attachments::stop_window_sessions(&state, window_label, own_token).await;
    for (token, cleanup) in stopped {
        if let Some(c) = cleanup {
            run_cleanup(&state, c).await;
        }
        match cause {
            WindowCloseCause::WindowDestroyed => {
                log::info!("resource-connect: window destroyed → session drop {token} (window {window_label})")
            }
            WindowCloseCause::RendererTerminated | WindowCloseCause::CloseUnanswered => log::warn!(
                target: "audit",
                "session.reaped: token={token} window={window_label} reason={}",
                cause.as_str()
            ),
        }
    }
}

/// How long app exit waits for session teardown.
const EXIT_STOP_BUDGET: Duration = Duration::from_secs(3);

/// `RunEvent::Exit`: stop every SSH/RDP session still live, run its
/// cleanup (the LDAP library check-in), and let the teardowns closing
/// windows started finish — within [`EXIT_STOP_BUDGET`].
///
/// Closing the last window exits the app from inside that window's
/// `Destroyed` event, so the teardown the event spawned would otherwise
/// race the process exit. The connections die with the process either
/// way; what this keeps is the check-in and the log line. Windows are not
/// touched — they go with the process.
pub fn stop_sessions_on_exit(app: &AppHandle) {
    let app = app.clone();
    let finished = tauri::async_runtime::block_on(async move {
        tokio::time::timeout(EXIT_STOP_BUDGET, async {
            let state = app.state::<AppState>();
            for (token, cleanup) in attachments::stop_all_sessions(&state).await {
                if let Some(c) = cleanup {
                    run_cleanup(&state, c).await;
                }
                log::info!("resource-connect: app exit → session drop {token}");
            }
            wait_for_teardowns().await;
        })
        .await
        .is_ok()
    });
    if !finished {
        log::warn!(
            target: "audit",
            "session.exit_teardown_incomplete: not every SSH/RDP session teardown finished within {}s",
            EXIT_STOP_BUDGET.as_secs()
        );
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
    /// T108 regression: no session window stops its sessions on the close
    /// *request* any more — that would end them before the page could ask,
    /// or after the operator cancelled. Both window builders install the
    /// one hook, which stops sessions on `Destroyed` and only arms the
    /// escape hatch on `CloseRequested`; a move destroys its source window
    /// rather than sending it a close its page would question.
    #[test]
    fn session_windows_stop_their_sessions_only_once_destroyed() {
        let read = |rel: &str| std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap();
        let connect = read("src/commands/connect.rs");
        assert!(!connect.contains("CloseRequested"), "connect.rs hooks a close request again");
        assert_eq!(connect.matches("session_workspace::hook_session_window_close(").count(), 2);

        let this = read("src/commands/session_workspace.rs");
        let hook = &this[this.find("pub(crate) fn hook_session_window_close").unwrap()..];
        let hook = &hook[..hook.find("\n}\n").unwrap()];
        let requested = &hook[hook.find("WindowEvent::CloseRequested").unwrap()..];
        let requested = &requested[..requested.find('\n').unwrap()];
        assert!(requested.contains("arm_close_escape_hatch"), "{requested}");
        assert!(!requested.contains("close_window_sessions"), "{requested}");
        assert!(hook.contains("WindowCloseCause::WindowDestroyed"));
        let moved = &this[this.find("pub async fn session_move").unwrap()..];
        let moved = &moved[..moved.find("\n}\n").unwrap()];
        assert!(moved.contains("win.destroy()") && !moved.contains("win.close()"));
    }

    #[test]
    fn the_workspace_capability_names_the_workspace_window_exactly() {
        assert_eq!(capability_windows("session-workspace.json"), [WORKSPACE_WINDOW_LABEL]);
        let default = capability_windows("default.json");
        for pattern in &default {
            assert!(!pattern.starts_with("session-"), "default.json reaches the workspace: {pattern}");
        }
    }
}
