//! `session_open_web` and `web_recipe_test` — Web Application Connect
//! (features/web-application-connect.md §3–§5, T96).
//!
//! Opens an ephemeral BastionVault window on a `web` connection profile's
//! start URL.
//!
//! * `login_mode: "open"` (Phase 1) releases no credential: the window is an
//!   audited, policy-bound launch point for applications that do their own
//!   login (typically SSO). Authorised by `v2/connect/authorize`.
//! * `login_mode: "form"` (Phase 2) calls `resources/v2/connect/web/launch`
//!   **instead of** `connect/authorize` (it burns the MFA ticket itself),
//!   opens the window on the bundle's `fill_scope.start_url` with the
//!   navigation allow-list built from `fill_scope.origins`, and runs the
//!   profile's login recipe through the fixed fill routine
//!   (`session::web_engine`). The outcome goes to `web/result` once and to
//!   the host-owned title; teardown always ends in `web/close`.
//! * `login_mode: "http-auth"` (Phase 3) also calls `launch` (exposure
//!   `handler`; a username and a password, no recipe, no TOTP). The window
//!   opens on `about:blank`, the native challenge handler
//!   (`commands::connect_web_http_auth`, decisions in
//!   `session::web_http_auth`) is attached, and only then does the window
//!   navigate to `fill_scope.start_url`, so no challenge can reach the
//!   platform's default handling first. The handler answers Basic / Digest /
//!   NTLM challenges on the scope's origins, once per (origin, realm); the
//!   credential never reaches the page. `result` / `close` and the outcome
//!   event work as for form mode.
//! * Any mode may carry `tls_pin_sha256` (Phase 4). The window then also
//!   opens on `about:blank`, the TLS pin handler
//!   (`commands::connect_web_tls_pin`, decisions in `session::web_tls_pin`)
//!   is attached with the HTTP-auth one, and only then does it navigate, so
//!   no certificate the platform rejects is decided without the pins. A pin
//!   overrides a rejection on the session's own https origins only; it never
//!   restricts a certificate the platform trusts.
//!
//! How the recipe talks to the page **without IPC**: the host evaluates the
//! fixed routine with the webview's native script evaluation
//! (`WebviewWindow::eval_with_callback` → WKWebView `evaluateJavaScript`,
//! WebView2 `ExecuteScript`, WebKitGTK `run_javascript`). The only thing that
//! travels back is the script's own return value, delivered to a host
//! closure. The page is never handed a channel, an `invoke` or a callback it
//! could call; it can at most make the routine's reply lie, and a reply can
//! only make the engine refuse or take the next host-decided step. No
//! `tauri::ipc::Channel` is used, so the web/RDP exclusion predicate is
//! unchanged.
//!
//! The window is deliberately a hostile-content container:
//!
//! * label `web-<token>`, which no capability file matches, so Tauri's ACL
//!   refuses every app and plugin command from it (remote origins are never
//!   granted IPC without an explicit `remote` capability, and none exists —
//!   both asserted by `capability_isolation_tests` below);
//! * `incognito`, plus a per-session `data_directory` on Windows / Linux
//!   removed when the session ends, so no cookie or storage outlives the
//!   session or is shared with the vault UI or another web session;
//! * an exact-origin allow-list on navigation, new windows and downloads;
//! * devtools off, Tauri's file drag-drop interception off;
//! * never alongside an RDP session: Tauri exempts its channel `fetch`
//!   endpoint from the remote-origin ACL, so the RDP frame channel could be
//!   read from here. Enforced in both directions by
//!   `session::web_rdp_conflict`, and decided before any credential is
//!   released;
//! * a host-owned window title (`<resource> — <origin>`, then the login
//!   state), never `document.title`.
//!
//! With the `web_session_chrome` build feature (Phase 5, off by default —
//! it turns on Tauri's crate-global `unstable` feature, see the GUI
//! manifest), the window holds two webviews: the remote content in its own
//! webview, labelled `web-<token>` like the window, and the vault-owned
//! toolbar (`session::web_chrome`, `commands::connect_web_chrome`) above
//! it, labelled `webchrome-<token>`, loading only the bundled
//! `web-chrome.html`. Every rule above applies to the remote webview
//! unchanged; the toolbar has no capability either. Without the feature the
//! window is the single remote webview of Phases 1–4.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::webview::{DownloadEvent, NewWindowResponse, PageLoadEvent};
#[cfg(not(feature = "web_session_chrome"))]
use tauri::WebviewWindowBuilder;
use tauri::{AppHandle, Emitter, EventTarget, Manager, State, Url, WebviewUrl};
use tokio::sync::Notify;

use bastion_vault::modules::resource::connect_web::recipe::{recipe_hash, WebLoginRecipe};

use super::connect::{
    collect_policy_hints, find_profile, read_effective_policy, read_resource_meta, record_recent_session,
    SessionProtocolTag,
};
use super::connect_web_http_auth::{InstallError, NativeGates, TLS_PIN_HANDLER_CHECK};
use crate::error::{CmdResult, CommandError};
use crate::session::web::{
    self as web_session, display_origin, download_decision, download_file_name, DownloadDecision, FormRelogin,
    NavigationVerdict, OriginSet, WebClipboard, WebCloseReason, WebLogin, WebOrigin, WebSessionKind, WebSessionState,
    WebShared, DATA_DIR_NAME, DEFAULT_WINDOW_HEIGHT, DEFAULT_WINDOW_WIDTH, WINDOW_LABEL_PREFIX,
};
use crate::session::web_chrome::{relogin_availability, Relogin};
use crate::session::web_engine::{
    run_check, run_fill, AuditTag, CheckReport, EngineTiming, EvalError, PageSnapshot, RecipePage,
};
use crate::session::web_http_auth::{
    GateAudit, GateEvent, HttpAuthCredential, HttpAuthGate, HttpAuthState, ANSWER_WINDOW,
};
use crate::session::web_launch::{self, LaunchChannel, LaunchRequest, WebLaunch};
use crate::session::web_recipe::{
    check_bundle, outcome_event, reconcile_fill_scope, BundleExpectation, EffectiveScope, ExpectedLogin,
    LaunchCredential, Outcome, PlanSteps, RecipePlan, UrlGlob, WebSessionOutcomeEvent, WEB_SESSION_OUTCOME_EVENT,
};
use crate::session::web_script::{parse_reply, render, ReplyError, ScriptCall, ScriptReply, MAX_REPLY_BYTES};
use crate::session::web_tls_pin::{PinAudit, PinRefusal, PinSet, TlsPinGate};
use crate::session::{registry_web_rdp_conflict, ProfileProtocol, SessionState, WebRdpConflict};
use crate::state::AppState;

/// How long one evaluation of the fill routine may take before the engine
/// treats it as "no result".
const EVAL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long attaching the native handlers (HTTP-auth challenge, TLS pin) may
/// take before the session is refused.
const HANDLER_INSTALL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long app exit waits for web launches to be reported and closed.
const EXIT_CLOSE_BUDGET: Duration = Duration::from_secs(3);

/// The vault UI window (`tauri.conf.json`), the only recipient of
/// [`WEB_SESSION_OUTCOME_EVENT`].
const MAIN_WINDOW_LABEL: &str = "main";

#[derive(Deserialize)]
pub struct WebOpenRequest {
    pub resource_name: String,
    pub profile_id: String,
    /// Single-use ticket from the connect-time MFA ceremony; required when
    /// the profile carries `require_mfa` (the server decides).
    #[serde(default)]
    pub connect_ticket: Option<String>,
}

#[derive(Serialize)]
pub struct WebOpenResponse {
    pub token: String,
    pub window_label: String,
    /// `open`, `form` or `http-auth`.
    pub login_mode: &'static str,
}

/// Why a web session may not run locally under the resource's effective
/// Rustion transport policy, or `None` when it may.
///
/// `rustion-required` means "no session on this resource touches the
/// operator's machine directly". A local web window does exactly that, and
/// there is no brokered web transport yet (Phase 8), so it is refused —
/// never silently opened locally. `rustion-preferred` permits the local
/// path, matching how SSH falls back when no bastion is usable.
pub(crate) fn web_transport_refusal(transport: &str, lock_violation: Option<&str>) -> Option<String> {
    if let Some(detail) = lock_violation {
        return Some(format!("rustion policy lock violation: {detail}"));
    }
    if transport == "rustion-required" {
        return Some(
            "this resource's transport policy is rustion-required, and web sessions cannot be brokered \
             through a Rustion bastion yet; refusing to open the application from this machine"
                .to_string(),
        );
    }
    None
}

#[tauri::command]
pub async fn session_open_web(
    state: State<'_, AppState>,
    app: AppHandle,
    request: WebOpenRequest,
) -> CmdResult<WebOpenResponse> {
    let meta = read_resource_meta(&state, &request.resource_name).await?;
    let profile = find_profile(&meta, &request.profile_id).ok_or_else(|| {
        CommandError::from(format!(
            "profile `{}` not found on resource `{}`",
            request.profile_id, request.resource_name
        ))
    })?;
    ProfileProtocol::require(&profile, ProfileProtocol::Web).map_err(CommandError::from)?;
    let cfg = web_session::parse_web_profile(&profile)
        .map_err(|e| CommandError::from(format!("web profile `{}`: {e}", request.profile_id)))?;

    // Early refusal, before the MFA pre-flight burns the operator's ticket.
    // The authoritative check is the one under the registry lock below.
    if let Some(conflict) = registry_web_rdp_conflict(ProfileProtocol::Web, &*state.connect_sessions.lock().await) {
        return Err(refuse_web_open(&request.resource_name, conflict));
    }

    // Transport policy. `connect/authorize` (open mode) does not look at the
    // Rustion tiers, so the host checks them first, before the ticket is
    // spent. A form or http-auth launch is checked by `launch` itself — server-side,
    // before the ticket is redeemed and before any credential is read — and
    // that check is authoritative, so the host does not repeat it (the two
    // used to disagree on a deployment with no `rustion/` mount).
    if matches!(cfg.login, WebLogin::Open) {
        let (resource_id, resource_type, asset_group_ids) =
            collect_policy_hints(&state, &request.resource_name, &meta).await;
        let effective = read_effective_policy(&state, &resource_id, &resource_type, &asset_group_ids).await?;
        if let Some(reason) = web_transport_refusal(&effective.transport, effective.lock_violation.as_deref()) {
            return Err(CommandError::from(reason));
        }
    }

    let token = crate::session::ssh::new_token();
    let window_label = format!("{WINDOW_LABEL_PREFIX}{token}");
    let kind = match cfg.login {
        WebLogin::Open => WebSessionKind::Open,
        WebLogin::Form(_) => WebSessionKind::Form,
        WebLogin::HttpAuth => WebSessionKind::HttpAuth,
    };
    let shared = WebShared::new(&request.resource_name, &display_origin(&cfg.start_url));

    // Reserve the registry slot before anything is authorised or released.
    // The RDP conflict is decided under the same lock that inserts the entry,
    // so an RDP session registering concurrently either sees this web
    // session or is seen by this check — never neither — and a form launch
    // never releases a credential for a session that cannot open.
    let data_dir = reserve_session(
        &state,
        &app,
        &token,
        WebSessionState {
            resource_name: request.resource_name.clone(),
            profile_id: request.profile_id.clone(),
            window_label: window_label.clone(),
            data_dir: None,
            opened_at: Instant::now(),
            kind,
            launch: None,
            shared: Arc::clone(&shared),
            relogin: None,
            engine: None,
        },
    )
    .await?;

    let mut form_run: Option<(LaunchStart, RecipePlan)> = None;
    let mut http_auth_run: Option<LaunchStart> = None;
    let scope = match &cfg.login {
        WebLogin::Open => {
            // Same server-side pre-flight as a direct SSH/RDP dial: checks
            // the `connect` grant and, on a `require_mfa` profile, verifies
            // and burns the ticket. Nothing is opened until it says yes.
            if let Err(e) = crate::commands::connect_mfa::authorize_direct(
                &state,
                &request.resource_name,
                &request.profile_id,
                request.connect_ticket.as_deref(),
            )
            .await
            {
                release_reservation(&state, &token).await;
                return Err(e);
            }
            EffectiveScope::local(cfg.start_url.clone(), cfg.origins.clone(), cfg.allow_insecure_http)
        }
        WebLogin::Form(form) => {
            let login = ExpectedLogin::Form { recipe_hash: &form.recipe_hash, plan: &form.plan };
            let start =
                launch_and_attach(&state, &request, &token, &cfg.origins, cfg.allow_insecure_http, login).await?;
            let scope = start.scope.clone();
            form_run = Some((start, form.plan.clone()));
            scope
        }
        WebLogin::HttpAuth => {
            let start = launch_and_attach(
                &state,
                &request,
                &token,
                &cfg.origins,
                cfg.allow_insecure_http,
                ExpectedLogin::HttpAuth,
            )
            .await?;
            let scope = start.scope.clone();
            http_auth_run = Some(start);
            scope
        }
    };

    // http-auth: the credential moves out of the bundle into the gate the
    // native handler consults. `check_bundle` guarantees both parts.
    let mut http_auth: Option<(Arc<HttpAuthGate>, tokio::sync::mpsc::UnboundedReceiver<GateEvent>)> = None;
    if let Some(start) = http_auth_run.as_mut() {
        let (Some(username), Some(password)) = (start.credential.username.take(), start.credential.password.take())
        else {
            shared.note_abort("credential_missing");
            close_web_session(&state, &app, &token, WebCloseReason::WindowBuildFailed).await;
            return Err(CommandError::from("the launch carried no complete credential; nothing was sent".to_string()));
        };
        http_auth = Some(HttpAuthGate::new(
            HttpAuthState::new(scope.origins.clone(), scope.allow_insecure_http),
            HttpAuthCredential::new(username, password),
            GateAudit {
                resource: request.resource_name.clone(),
                token: token.clone(),
                launch_id_hash: start.launch.launch_id_hash().to_string(),
            },
        ));
    }
    let http_auth_gate = http_auth.as_ref().map(|(g, _)| Arc::clone(g));

    // TLS pins (Phase 4), honoured on the session's effective origins — for
    // a launch, the server's scope.
    let launch_id_hash = form_run
        .as_ref()
        .map(|(start, _)| start.launch.launch_id_hash().to_string())
        .or_else(|| http_auth_run.as_ref().map(|start| start.launch.launch_id_hash().to_string()));
    let tls_pin_gate = (!cfg.tls_pins.is_empty()).then(|| {
        pin_gate(
            &app,
            &window_label,
            &shared,
            &cfg.tls_pins,
            &scope.origins,
            PinAudit {
                resource: request.resource_name.clone(),
                token: token.clone(),
                launch_id_hash: launch_id_hash.clone(),
            },
        )
    });
    let gates = NativeGates { http_auth: http_auth_gate.clone(), tls_pin: tls_pin_gate };

    // A window with native handlers starts on `about:blank` and is sent to
    // the start URL only once they are attached (below).
    let initial_url = if !gates.is_empty() {
        Url::parse("about:blank").map_err(|e| CommandError::from(format!("about:blank: {e}")))?
    } else {
        scope.start_url.clone()
    };
    let win = match build_window(
        &app,
        &window_label,
        &token,
        &request.resource_name,
        &cfg,
        &scope,
        &shared,
        data_dir,
        initial_url,
        http_auth_gate.clone(),
    ) {
        Ok(w) => w,
        Err(e) => {
            if let Some(g) = &http_auth_gate {
                g.release();
            }
            close_web_session(&state, &app, &token, WebCloseReason::WindowBuildFailed).await;
            return Err(e);
        }
    };
    hook_window_destroyed(&win.window, &app, &token);

    if !gates.is_empty() {
        if let Err(InstallError { check, reason }) = arm_native_handlers(&win.remote, gates, &scope.start_url).await {
            log::warn!(
                target: "audit",
                "connect.web.refused: reason={check} resource={} profile={}{} — {reason}",
                request.resource_name,
                request.profile_id,
                launch_id_hash.as_deref().map(|h| format!(" launch_id_hash={h}")).unwrap_or_default(),
            );
            if let Some(g) = &http_auth_gate {
                g.release();
            }
            shared.note_abort(check);
            close_web_session(&state, &app, &token, WebCloseReason::WindowBuildFailed).await;
            let what = if check == TLS_PIN_HANDLER_CHECK {
                "honour this profile's TLS certificate pins"
            } else {
                "answer HTTP authentication challenges"
            };
            let closed = if launch_id_hash.is_some() {
                "the launch was closed and no credential was sent"
            } else {
                "the session was closed before the application was loaded"
            };
            return Err(CommandError::from(format!("this webview cannot {what} ({reason}); {closed}")));
        }
    }

    let start_origin = display_origin(&scope.start_url);
    match (&form_run, &http_auth_run) {
        (Some((start, plan)), _) => log::info!(
            target: "audit",
            "session.open: protocol=web login_mode=form resource={} profile={} origin={} fill_origins={} \
             narrowed_out={} heuristic={} credential_source={} mfa={} launch_id_hash={} downloads={} popups={} \
             clipboard={:?} tls_pins={} token={}",
            request.resource_name,
            request.profile_id,
            start_origin,
            scope.origins,
            start.narrowed_out_count,
            plan.is_heuristic(),
            start.credential_source,
            start.mfa_method.as_deref().unwrap_or("none"),
            start.launch.launch_id_hash(),
            cfg.allow_downloads,
            cfg.allow_popups,
            cfg.clipboard,
            cfg.tls_pins.len(),
            token,
        ),
        (None, Some(start)) => log::info!(
            target: "audit",
            "session.open: protocol=web login_mode=http-auth resource={} profile={} origin={} answer_origins={} \
             narrowed_out={} exposure={} credential_source={} mfa={} launch_id_hash={} downloads={} popups={} \
             clipboard={:?} tls_pins={} token={}",
            request.resource_name,
            request.profile_id,
            start_origin,
            scope.origins,
            start.narrowed_out_count,
            start.exposure,
            start.credential_source,
            start.mfa_method.as_deref().unwrap_or("none"),
            start.launch.launch_id_hash(),
            cfg.allow_downloads,
            cfg.allow_popups,
            cfg.clipboard,
            cfg.tls_pins.len(),
            token,
        ),
        (None, None) => log::info!(
            target: "audit",
            "session.open: protocol=web login_mode=open resource={} profile={} origin={} allowed_origins={} \
             downloads={} popups={} clipboard={:?} tls_pins={} token={}",
            request.resource_name,
            request.profile_id,
            start_origin,
            scope.origins,
            cfg.allow_downloads,
            cfg.allow_popups,
            cfg.clipboard,
            cfg.tls_pins.len(),
            token,
        ),
    }

    let login_mode = if let Some((start, plan)) = form_run {
        // What a re-run login from the toolbar needs: the recipe and the
        // window's allow-list. No credential.
        let relogin = match &cfg.login {
            WebLogin::Form(form) => Some(Arc::new(FormRelogin {
                origins: scope.origins.clone(),
                allow_insecure_http: scope.allow_insecure_http,
                form: (**form).clone(),
            })),
            _ => None,
        };
        let engine = spawn_recipe_engine(
            &app,
            &window_label,
            &token,
            &request.resource_name,
            &request.profile_id,
            &shared,
            plan,
            scope,
            start,
        );
        attach_engine(&state, &token, engine, relogin).await;
        "form"
    } else if let (Some(start), Some((gate, events))) = (http_auth_run, http_auth) {
        spawn_http_auth_reporter(
            &app,
            &window_label,
            &token,
            &request.resource_name,
            &request.profile_id,
            &shared,
            gate,
            events,
            start.launch,
        );
        "http-auth"
    } else {
        "open"
    };

    let _ = record_recent_session(&state, &request.resource_name, &profile, SessionProtocolTag::Web).await;

    Ok(WebOpenResponse { token, window_label, login_mode })
}

/// What a successful `launch` hands the window and the engine (form) or the
/// challenge handler (http-auth).
struct LaunchStart {
    scope: EffectiveScope,
    launch: Arc<WebLaunch>,
    credential: LaunchCredential,
    refresh_steps: Vec<u32>,
    credential_source: String,
    exposure: String,
    mfa_method: Option<String>,
    narrowed_out_count: usize,
}

/// [`start_launch`], then attach the launch to the reserved registry entry.
/// On failure the reservation is released (and a launch that exists is
/// closed) before the error returns.
async fn launch_and_attach(
    state: &State<'_, AppState>,
    request: &WebOpenRequest,
    token: &str,
    origins: &OriginSet,
    allow_insecure_http: bool,
    login: ExpectedLogin<'_>,
) -> CmdResult<LaunchStart> {
    let start = match start_launch(state, request, token, origins, allow_insecure_http, login).await {
        Ok(s) => s,
        Err(e) => {
            release_reservation(state, token).await;
            return Err(e);
        }
    };
    if !attach_launch(state, token, &start.launch).await {
        // Removed while the launch was in flight; nothing else will finish
        // this launch.
        start.launch.finish("session_closed").await;
        return Err(CommandError::from("the web session was closed while it was being opened".to_string()));
    }
    Ok(start)
}

/// `v2/connect/web/launch`, then the bundle checks. Any check that fails
/// after the server created the launch reports `aborted:<check>` and closes
/// it before the error returns; the credential is dropped with the bundle.
/// The server's fill scope must fit inside `origins` (the profile's set
/// on open, the window's allow-list on a re-run).
async fn start_launch(
    state: &State<'_, AppState>,
    request: &WebOpenRequest,
    token: &str,
    origins: &OriginSet,
    allow_insecure_http: bool,
    login: ExpectedLogin<'_>,
) -> CmdResult<LaunchStart> {
    let channel = LaunchChannel::capture(state).await.map_err(CommandError::from)?;
    let recipe_hash = match login {
        ExpectedLogin::Form { recipe_hash, .. } => Some(recipe_hash),
        ExpectedLogin::HttpAuth => None,
    };
    let launch_request = LaunchRequest {
        resource: &request.resource_name,
        profile_id: &request.profile_id,
        recipe_hash,
        connect_ticket: request.connect_ticket.as_deref(),
        session_token: token,
    };
    let (launch, bundle) = web_launch::launch(channel, &launch_request).await.map_err(|e| {
        log::warn!(
            target: "audit",
            "connect.web.refused: reason=launch_refused code={} resource={} profile={}",
            web_launch::refusal_code(&e),
            request.resource_name,
            request.profile_id,
        );
        CommandError::from(e)
    })?;

    let expect = BundleExpectation { resource: &request.resource_name, profile_id: &request.profile_id, login };
    if let Err(check) = check_bundle(&bundle, &expect) {
        drop(bundle);
        log::warn!(
            target: "audit",
            "connect.web.refused: reason={check} resource={} profile={} launch_id_hash={}",
            request.resource_name,
            request.profile_id,
            launch.launch_id_hash(),
        );
        launch.finish(check).await;
        return Err(CommandError::from(format!(
            "the server's launch does not match this profile ({check}); nothing was filled or sent — reload the \
             resource and connect again"
        )));
    }
    let scope = match reconcile_fill_scope(origins, allow_insecure_http, &bundle.fill_scope) {
        Ok(s) => s,
        Err(e) => {
            drop(bundle);
            log::warn!(
                target: "audit",
                "connect.web.refused: reason=fill_scope resource={} profile={} launch_id_hash={}",
                request.resource_name,
                request.profile_id,
                launch.launch_id_hash(),
            );
            launch.finish("fill_scope").await;
            return Err(CommandError::from(format!("refusing the launch: {e}; nothing was filled or sent")));
        }
    };
    if !scope.narrowed_out.is_empty() {
        log::info!(
            target: "audit",
            "connect.web.fill_scope_narrowed: resource={} profile={} launch_id_hash={} dropped={}",
            request.resource_name,
            request.profile_id,
            launch.launch_id_hash(),
            scope.narrowed_out.join(","),
        );
    }
    let narrowed_out_count = scope.narrowed_out.len();
    Ok(LaunchStart {
        scope,
        launch,
        credential: bundle.credential,
        refresh_steps: bundle.totp_refresh_steps,
        credential_source: bundle.credential_source,
        exposure: bundle.exposure,
        mfa_method: bundle.mfa_method,
        narrowed_out_count,
    })
}

/// Insert a web session entry, refusing (and audited) when an RDP session
/// is live. Creates the per-session data directory first, so the entry
/// owns it from the moment it exists; returns it for the window builder.
async fn reserve_session(
    state: &State<'_, AppState>,
    app: &AppHandle,
    token: &str,
    mut entry: WebSessionState,
) -> CmdResult<Option<PathBuf>> {
    entry.data_dir = prepare_data_dir(app, token)?;
    let data_dir = entry.data_dir.clone();
    let mut sessions = state.connect_sessions.lock().await;
    if let Some(conflict) = registry_web_rdp_conflict(ProfileProtocol::Web, &sessions) {
        drop(sessions);
        if let Some(dir) = entry.data_dir {
            web_session::remove_data_dir_eventually(dir);
        }
        return Err(refuse_web_open(&entry.resource_name, conflict));
    }
    sessions.insert(token.to_string(), SessionState::Web(entry));
    Ok(data_dir)
}

/// Undo [`reserve_session`] when the open failed before a window or a launch
/// existed. No `session.close` line: no `session.open` was written.
async fn release_reservation(state: &AppState, token: &str) {
    let removed = {
        let mut sessions = state.connect_sessions.lock().await;
        match sessions.get(token) {
            Some(SessionState::Web(_)) => sessions.remove(token),
            _ => None,
        }
    };
    if let Some(SessionState::Web(w)) = removed {
        if let Some(launch) = &w.launch {
            launch.finish("session_closed").await;
        }
        if let Some(dir) = w.data_dir {
            web_session::remove_data_dir_eventually(dir);
        }
    }
}

/// Attach a launch to its reserved entry; `false` when the entry is gone.
async fn attach_launch(state: &AppState, token: &str, launch: &Arc<WebLaunch>) -> bool {
    let mut sessions = state.connect_sessions.lock().await;
    match sessions.get_mut(token) {
        Some(SessionState::Web(w)) => {
            w.launch = Some(Arc::clone(launch));
            true
        }
        _ => false,
    }
}

/// Record a form session's recipe engine and re-run context on its entry.
/// When the entry is already gone the engine stops on its own (teardown
/// cancelled its launch and marked the page closed).
async fn attach_engine(
    state: &AppState,
    token: &str,
    engine: tauri::async_runtime::JoinHandle<()>,
    relogin: Option<Arc<FormRelogin>>,
) {
    let mut sessions = state.connect_sessions.lock().await;
    if let Some(SessionState::Web(w)) = sessions.get_mut(token) {
        w.engine = Some(engine);
        if relogin.is_some() {
            w.relogin = relogin;
        }
    }
}

/// Audit and build the operator-facing error for a web open refused by the
/// web/RDP exclusion. No profile, credential or URL detail is logged.
fn refuse_web_open(resource: &str, conflict: WebRdpConflict) -> CommandError {
    log::warn!(
        target: "audit",
        "connect.web.refused: reason={} resource={resource}",
        conflict.audit_reason,
    );
    CommandError::from(conflict.message)
}

// ── Teardown ───────────────────────────────────────────────────────

/// Teardowns between taking a session out of the registry and finishing its
/// launch. App exit waits for these, so a window closed by the quit itself
/// still gets its `web/close`.
static CLOSES_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static CLOSES_IDLE: Notify = Notify::const_new();

struct InFlightClose;

impl InFlightClose {
    fn begin() -> Self {
        CLOSES_IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for InFlightClose {
    fn drop(&mut self) {
        if CLOSES_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst) == 1 {
            CLOSES_IDLE.notify_waiters();
        }
    }
}

async fn wait_for_closes() {
    loop {
        let idle = CLOSES_IDLE.notified();
        tokio::pin!(idle);
        idle.as_mut().enable();
        if CLOSES_IN_FLIGHT.load(Ordering::SeqCst) == 0 {
            return;
        }
        idle.await;
    }
}

/// Tear down a web session: drop its registry entry, destroy its window,
/// stop its recipe engine, report and close its launch, write the close
/// audit line and remove its data directory. Returns `false` when `token`
/// doesn't name a live web session (so the caller can try the SSH/RDP
/// paths). Idempotent: the window-destroyed hook and an explicit
/// `session_close` can both call it.
pub(crate) async fn close_web_session(state: &AppState, app: &AppHandle, token: &str, reason: WebCloseReason) -> bool {
    let _in_flight = InFlightClose::begin();
    let removed = {
        let mut sessions = state.connect_sessions.lock().await;
        match sessions.get(token) {
            Some(SessionState::Web(_)) => sessions.remove(token),
            _ => None,
        }
    };
    let Some(SessionState::Web(session)) = removed else {
        return false;
    };
    if let Some(win) = session_window(app, &session.window_label) {
        let _ = win.destroy();
    }
    web_session::finish_session(token, session, reason).await;
    true
}

/// `RunEvent::Exit`: report and close every web launch still open, within
/// [`EXIT_CLOSE_BUDGET`], including teardowns the closing windows already
/// started. Windows are not touched — they are going away with the process.
/// A launch that cannot be closed in time is reaped by the server, and an
/// LDAP account it checked out is released when its lease expires.
pub fn close_web_sessions_on_exit(app: &AppHandle) {
    let app = app.clone();
    let finished = tauri::async_runtime::block_on(async move {
        tokio::time::timeout(EXIT_CLOSE_BUDGET, async {
            let state = app.state::<AppState>();
            let sessions: Vec<(String, WebSessionState)> = {
                let mut map = state.connect_sessions.lock().await;
                let tokens: Vec<String> =
                    map.iter().filter(|(_, s)| matches!(s, SessionState::Web(_))).map(|(t, _)| t.clone()).collect();
                tokens
                    .into_iter()
                    .filter_map(|t| match map.remove(&t) {
                        Some(SessionState::Web(w)) => Some((t, w)),
                        _ => None,
                    })
                    .collect()
            };
            for (token, session) in sessions {
                web_session::finish_session(&token, session, WebCloseReason::AppExit).await;
            }
            // Teardowns the closing windows started before this ran.
            wait_for_closes().await;
        })
        .await
        .is_ok()
    });
    if !finished {
        log::warn!(
            target: "audit",
            "connect.web.close_failed: reason=app_exit — not every web launch was closed within {}s; the server \
             reaps them",
            EXIT_CLOSE_BUDGET.as_secs()
        );
    }
}

fn hook_window_destroyed(win: &tauri::Window, app: &AppHandle, token: &str) {
    let token = token.to_string();
    let app = app.clone();
    win.on_window_event(move |ev| {
        if let tauri::WindowEvent::Destroyed = ev {
            let token = token.clone();
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let s = app.state::<AppState>();
                close_web_session(&s, &app, &token, WebCloseReason::WindowClosed).await;
            });
        }
    });
}

// ── The recipe engine's view of the window ─────────────────────────

/// [`RecipePage`] over a live session window. The page state comes from the
/// window's own navigation events (host-observed); the only way in is the
/// fixed routine through the webview's native script evaluation.
struct TauriPage {
    app: AppHandle,
    label: String,
    shared: Arc<WebShared>,
}

impl RecipePage for TauriPage {
    fn snapshot(&self) -> PageSnapshot {
        self.shared.snapshot()
    }

    fn closed(&self) -> bool {
        self.shared.is_closed()
    }

    fn eval(&self, call: &ScriptCall<'_>) -> impl std::future::Future<Output = Result<ScriptReply, EvalError>> + Send {
        let mut script = render(call);
        let app = self.app.clone();
        let label = self.label.clone();
        async move {
            // `None`: the reply was over `MAX_REPLY_BYTES` and was dropped
            // in the callback, never handed on or parsed.
            let (tx, rx) = tokio::sync::oneshot::channel::<Option<String>>();
            let tx = std::sync::Mutex::new(Some(tx));
            {
                let Some(win) = remote_webview(&app, &label) else {
                    return Err(EvalError::WindowGone);
                };
                // Moves the buffer out; the zeroizing wrapper is left empty.
                let js = std::mem::take(&mut *script);
                let sent = win.eval_with_callback(js, move |raw| {
                    if let Some(tx) = tx.lock().ok().and_then(|mut g| g.take()) {
                        let _ = tx.send((raw.len() <= MAX_REPLY_BYTES).then_some(raw));
                    }
                });
                if sent.is_err() {
                    return Err(EvalError::WindowGone);
                }
            }
            match tokio::time::timeout(EVAL_TIMEOUT, rx).await {
                Ok(Ok(None)) => Err(EvalError::Invalid),
                Ok(Ok(Some(raw))) => parse_reply(&raw).map_err(|e| match e {
                    ReplyError::NoResult => EvalError::NoResult,
                    ReplyError::Invalid => EvalError::Invalid,
                }),
                Ok(Err(_)) => Err(EvalError::NoResult),
                Err(_) => Err(EvalError::Timeout),
            }
        }
    }

    fn show(&self, text: &str) {
        let title = self.shared.set_login(text);
        set_title_later(&self.app, &self.label, title);
    }
}

/// Tell the vault UI how a form session's sign-in ended. Sent to the main
/// window only: Tauri delivers an event by evaluating it in the webviews that
/// registered a JS listener for it, and a `web-*` window cannot register one
/// (it has no capability, so the ACL refuses `plugin:event|listen`). This is
/// an event, not a `tauri::ipc::Channel`, so the web/RDP exclusion predicate
/// is unaffected.
fn emit_outcome(app: &AppHandle, event: &WebSessionOutcomeEvent) {
    let target = EventTarget::WebviewWindow { label: MAIN_WINDOW_LABEL.to_string() };
    if let Err(e) = app.emit_to(target, WEB_SESSION_OUTCOME_EVENT, event) {
        log::warn!("connect.web: could not tell the main window the sign-in outcome: {e}");
    }
}

/// Run the recipe for a form session, then report the outcome once — to the
/// server and to the main window. The credential moves into the engine and
/// is dropped when it returns. The toolbar's sign-in window runs for the
/// recipe's timeout and closes with the engine.
#[allow(clippy::too_many_arguments)]
fn spawn_recipe_engine(
    app: &AppHandle,
    label: &str,
    token: &str,
    resource: &str,
    profile_id: &str,
    shared: &Arc<WebShared>,
    plan: RecipePlan,
    scope: EffectiveScope,
    start: LaunchStart,
) -> tauri::async_runtime::JoinHandle<()> {
    let page = TauriPage { app: app.clone(), label: label.to_string(), shared: Arc::clone(shared) };
    let app = app.clone();
    let token = token.to_string();
    let resource = resource.to_string();
    let profile_id = profile_id.to_string();
    let shared = Arc::clone(shared);
    let login_window = shared.start_login_window(plan.timeout);
    tauri::async_runtime::spawn(async move {
        let login_window = LoginWindowGuard { shared: &shared, ticket: login_window };
        let LaunchStart { launch, credential, refresh_steps, .. } = start;
        let audit = AuditTag { resource: &resource, token: &token, launch_id_hash: launch.launch_id_hash() };
        let report = run_fill(
            &plan,
            &scope,
            credential,
            refresh_steps,
            &page,
            &*launch,
            launch.cancel_rx(),
            EngineTiming::for_plan(&plan),
            audit,
        )
        .await;
        // The credential went with the engine.
        drop(login_window);
        log::info!(
            target: "audit",
            "connect.web.login: resource={resource} token={token} launch_id_hash={} outcome={} step={} fills={}",
            launch.launch_id_hash(),
            report.outcome.wire(),
            report.step.map(|s| s.to_string()).unwrap_or_else(|| "none".into()),
            report.fills,
        );
        launch.report(&report.outcome, report.step).await;
        emit_outcome(&app, &outcome_event(&token, &resource, &profile_id, &report.outcome, report.step));
    })
}

// ── Re-run login (Phase 5, the session toolbar) ───────────────────

/// The `aborted:<check>` a launch retired by a re-run is closed with, when
/// its recipe had not reported an outcome yet.
pub(crate) const RELOGIN_CHECK: &str = "relogin";

/// How long a re-run waits for the previous recipe engine to stop and report
/// before closing that launch anyway (one fill-routine evaluation).
const RELOGIN_ENGINE_STOP: Duration = EVAL_TIMEOUT;

/// Sign a `form` session in again, in its existing window.
///
/// Nothing is replayed: a **new** `v2/connect/web/launch` is made (new
/// `launch_id`, the server's `connect` authorisation and audit, a fresh
/// credential and TOTP code), with the recipe the session was opened with,
/// and its fill scope must fit the window's allow-list. The connect MFA
/// ticket is single-use and the toolbar cannot run the ceremony, so none is
/// sent: on a profile the server gates on MFA, the launch is refused and the
/// session is left exactly as it was. Only once the new launch is checked
/// is the previous one retired — its engine stopped (`aborted:relogin`
/// when it had not reported) and the launch closed, which also checks an
/// LDAP account back in. The page is then sent to the start URL and the
/// recipe runs on it. A failure before the swap changes nothing.
pub(crate) async fn relogin_web_session(state: &State<'_, AppState>, app: &AppHandle, token: &str) -> CmdResult<()> {
    let (resource, profile_id, label, shared, relogin) = {
        let sessions = state.connect_sessions.lock().await;
        let Some(SessionState::Web(w)) = sessions.get(token) else {
            return Err(CommandError::from("this web session has ended".to_string()));
        };
        match relogin_availability(w.kind, w.shared.relogin_running()) {
            Relogin::Available => {}
            Relogin::Running => {
                return Err(CommandError::from("a sign-in re-run is already in progress".to_string()));
            }
            Relogin::Unavailable(reason) => return Err(CommandError::from(reason.to_string())),
        }
        let Some(relogin) = w.relogin.clone() else {
            return Err(CommandError::from("this session's first sign-in has not started yet".to_string()));
        };
        (w.resource_name.clone(), w.profile_id.clone(), w.window_label.clone(), Arc::clone(&w.shared), relogin)
    };
    let Some(_running) = shared.begin_relogin() else {
        return Err(CommandError::from("a sign-in re-run is already in progress".to_string()));
    };
    log::info!(
        target: "audit",
        "connect.web.relogin: state=requested resource={resource} profile={profile_id} token={token}"
    );

    let request =
        WebOpenRequest { resource_name: resource.clone(), profile_id: profile_id.clone(), connect_ticket: None };
    let login = ExpectedLogin::Form { recipe_hash: &relogin.form.recipe_hash, plan: &relogin.form.plan };
    let start = match start_launch(state, &request, token, &relogin.origins, relogin.allow_insecure_http, login).await {
        Ok(s) => s,
        Err(e) => {
            // `start_launch` audited the refusal and closed any launch it
            // created; the session keeps its current launch.
            log::info!(
                target: "audit",
                "connect.web.relogin: state=refused resource={resource} profile={profile_id} token={token}"
            );
            return Err(e);
        }
    };

    // Swap the launches on the entry.
    let swapped = {
        let mut sessions = state.connect_sessions.lock().await;
        match sessions.get_mut(token) {
            Some(SessionState::Web(w)) => Some((w.launch.replace(Arc::clone(&start.launch)), w.engine.take())),
            _ => None,
        }
    };
    let Some((previous, previous_engine)) = swapped else {
        start.launch.finish("session_closed").await;
        return Err(CommandError::from(
            "the web session ended during the re-run; the new launch was closed and nothing was filled".to_string(),
        ));
    };

    // Retire the previous launch: stop its engine and let it report, then
    // close it (checking an LDAP account back in).
    let previous_hash = previous.as_ref().map(|l| l.launch_id_hash().to_string()).unwrap_or_else(|| "none".into());
    if let Some(previous) = previous {
        previous.cancel(RELOGIN_CHECK);
        if let Some(engine) = previous_engine {
            let _ = tokio::time::timeout(RELOGIN_ENGINE_STOP, engine).await;
        }
        previous.finish(RELOGIN_CHECK).await;
    }
    log::info!(
        target: "audit",
        "connect.web.relogin: state=launched resource={resource} profile={profile_id} token={token} \
         previous_launch_id_hash={previous_hash} launch_id_hash={} credential_source={} mfa={}",
        start.launch.launch_id_hash(),
        start.credential_source,
        start.mfa_method.as_deref().unwrap_or("none"),
    );

    // A fresh login page: the engine waits for the host to see it load.
    shared.expect_navigation();
    match remote_webview(app, &label) {
        Some(remote) => {
            if let Err(e) = remote.navigate(start.scope.start_url.clone()) {
                log::warn!("connect.web.relogin: could not open the start URL: {e}");
            }
        }
        // Gone with the window: the engine sees the page closed and reports.
        None => log::warn!("connect.web.relogin: the session window is gone"),
    }
    let plan = relogin.form.plan.clone();
    let scope = start.scope.clone();
    let engine = spawn_recipe_engine(app, &label, token, &resource, &profile_id, &shared, plan, scope, start);
    attach_engine(state, token, engine, None).await;
    Ok(())
}

/// Closes a sign-in window when the task that opened it ends, however it
/// ends (outcome, cancel, or the task being dropped).
struct LoginWindowGuard<'a> {
    shared: &'a WebShared,
    ticket: web_session::LoginWindowTicket,
}

impl Drop for LoginWindowGuard<'_> {
    fn drop(&mut self) {
        self.shared.end_login_window(self.ticket);
    }
}

// ── http-auth ──────────────────────────────────────────────────────

/// Attach the native handlers (HTTP-auth challenge, TLS pin), then — only
/// then — send the window from `about:blank` to the start URL. `Err` names
/// the handler (its `aborted:<check>`) and carries a reason safe to show; the
/// caller closes the session and its launch.
async fn arm_native_handlers(win: &tauri::Webview, gates: NativeGates, start_url: &Url) -> Result<(), InstallError> {
    let check = if gates.http_auth.is_some() {
        super::connect_web_http_auth::HTTP_AUTH_HANDLER_CHECK
    } else {
        TLS_PIN_HANDLER_CHECK
    };
    let failed = |reason: &str| InstallError { check, reason: reason.to_string() };
    let installed = super::connect_web_http_auth::install(win, gates);
    match tokio::time::timeout(HANDLER_INSTALL_TIMEOUT, installed).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => return Err(e),
        Ok(Err(_)) => return Err(failed("the session window closed before the handler was attached")),
        Err(_) => return Err(failed("attaching the handler timed out")),
    }
    win.navigate(start_url.clone()).map_err(|e| failed(&format!("open the start URL: {e}")))
}

/// The TLS pin gate of one window. A refusal is shown in the title (fixed
/// text) and becomes the session's abort reason if it ends before an
/// outcome.
fn pin_gate(
    app: &AppHandle,
    label: &str,
    shared: &Arc<WebShared>,
    pins: &PinSet,
    origins: &OriginSet,
    audit: PinAudit,
) -> Arc<TlsPinGate> {
    let app = app.clone();
    let label = label.to_string();
    let hook_shared = Arc::clone(shared);
    let gate = TlsPinGate::new(
        pins.clone(),
        origins.clone(),
        audit,
        Box::new(move |refusal: PinRefusal| {
            hook_shared.note_abort(refusal.check());
            set_title_later(&app, &label, hook_shared.set_notice(refusal.notice().to_string()));
        }),
    );
    // For the toolbar's lock indicator (held weakly: the hook above holds
    // `shared`).
    shared.attach_pin_gate(&gate);
    gate
}

/// Drive an http-auth session's reporting: the outcome the gate settles goes
/// to `web/result` once, to the title and to the main window; refusals show
/// in the title; the answer window's end drops the credential (and settles
/// `timeout` / `aborted:<refusal>` if nothing did); teardown drops it at
/// once. Ends with the session.
#[allow(clippy::too_many_arguments)]
fn spawn_http_auth_reporter(
    app: &AppHandle,
    label: &str,
    token: &str,
    resource: &str,
    profile_id: &str,
    shared: &Arc<WebShared>,
    gate: Arc<HttpAuthGate>,
    mut events: tokio::sync::mpsc::UnboundedReceiver<GateEvent>,
    launch: Arc<WebLaunch>,
) {
    let app = app.clone();
    let label = label.to_string();
    let token = token.to_string();
    let resource = resource.to_string();
    let profile_id = profile_id.to_string();
    let shared = Arc::clone(shared);
    set_title_later(&app, &label, shared.set_login("waiting for the sign-in challenge"));
    let answer_window = shared.start_login_window(ANSWER_WINDOW);
    tauri::async_runtime::spawn(async move {
        let mut login_window = Some(LoginWindowGuard { shared: &shared, ticket: answer_window });
        let mut cancel = launch.cancel_rx();
        let deadline = tokio::time::sleep(ANSWER_WINDOW);
        tokio::pin!(deadline);
        let mut window_open = true;
        let report = |outcome: Outcome| {
            let app = app.clone();
            let label = label.clone();
            let token = token.clone();
            let resource = resource.clone();
            let profile_id = profile_id.clone();
            let shared = Arc::clone(&shared);
            let launch = Arc::clone(&launch);
            async move {
                set_title_later(&app, &label, shared.set_login(&outcome.title_text()));
                log::info!(
                    target: "audit",
                    "connect.web.login: resource={resource} token={token} launch_id_hash={} outcome={} step=none \
                     login_mode=http-auth",
                    launch.launch_id_hash(),
                    outcome.wire(),
                );
                launch.report(&outcome, None).await;
                emit_outcome(&app, &outcome_event(&token, &resource, &profile_id, &outcome, None));
            }
        };
        while cancel.borrow().is_none() {
            tokio::select! {
                ev = events.recv() => match ev {
                    Some(GateEvent::Outcome(o)) => report(o).await,
                    Some(GateEvent::Notice(text)) => set_title_later(&app, &label, shared.set_notice(text.to_string())),
                    None => break,
                },
                () = &mut deadline, if window_open => {
                    window_open = false;
                    // The gate drops the credential with the answer window.
                    drop(login_window.take());
                    if let Some(o) = gate.expire() {
                        report(o).await;
                    }
                }
                changed = cancel.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
        // Teardown (or the launch going away): the credential goes now.
        gate.release();
    });
}

// ── web_recipe_test ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WebRecipeTestRequest {
    /// The page to open (normally the profile's start URL).
    pub url: String,
    /// The recipe as it would be stored on the profile.
    pub recipe: Value,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// The profile's `tls_pin_sha256`, so a dry run reaches an appliance with
    /// a self-signed certificate the same way the session will (Phase 4).
    #[serde(default)]
    pub tls_pin_sha256: Vec<String>,
}

#[derive(Serialize)]
pub struct WebRecipeTestResponse {
    /// What `launch` would require as `recipe_hash` for this recipe.
    pub recipe_hash: String,
    pub report: CheckReport,
}

/// The dry-run scope: the URL's origin plus `allowed_origins`, under the
/// same rules as a profile; every recipe URL must sit on it (spec §2).
fn recipe_test_scope(request: &WebRecipeTestRequest, plan: &RecipePlan) -> Result<EffectiveScope, String> {
    let http = request.allow_insecure_http;
    let start_url = Url::parse(request.url.trim()).map_err(|e| format!("the test URL is not a valid URL: {e}"))?;
    if !start_url.username().is_empty() || start_url.password().is_some() {
        return Err("the test URL carries userinfo (`user@host`)".into());
    }
    let mut origins = vec![WebOrigin::validated(&start_url, http).map_err(|e| format!("test URL: {e}"))?];
    for raw in &request.allowed_origins {
        origins.push(WebOrigin::parse_config(raw, http)?);
    }
    let set = OriginSet::new(origins);
    let mut globs: Vec<&UrlGlob> = Vec::new();
    if let PlanSteps::Explicit(steps) = &plan.steps {
        globs.extend(steps.iter().map(|s| &s.when_url));
    }
    globs.extend(plan.success.url.iter());
    globs.extend(plan.failure.iter().filter_map(|f| f.url.as_ref()));
    if let Some(g) = globs.iter().find(|g| !set.contains(g.origin())) {
        return Err(format!(
            "the recipe matches on {}, which is not the test URL's origin or an allowed origin",
            g.origin()
        ));
    }
    Ok(EffectiveScope::local(start_url, set, http))
}

/// Dry-run a login recipe against a URL (spec Phase 2).
///
/// No credential exists anywhere on this path: nothing is read from the
/// vault, `launch` is never called, no MFA ticket is involved, and the
/// engine runs in check mode only (`run_check` has no credential parameter)
/// — every safety check of the fill routine runs, but no value is set, no
/// button is clicked and no form is submitted, so the target sees no login
/// attempt. The window is a full web session window (IPC-less, ephemeral
/// store, origin allow-list) and counts for the web/RDP exclusion. Pages
/// after the first are checked when the operator signs in by hand inside
/// the test window. Returns per-step selector results when every step was
/// seen or the recipe's timeout passed, then closes the window.
#[tauri::command]
pub async fn web_recipe_test(
    state: State<'_, AppState>,
    app: AppHandle,
    request: WebRecipeTestRequest,
) -> CmdResult<WebRecipeTestResponse> {
    let recipe = WebLoginRecipe::parse(&request.recipe).map_err(|e| CommandError::from(e.to_string()))?;
    let hash = recipe_hash(&request.recipe).map_err(|e| CommandError::from(e.to_string()))?;
    let plan = RecipePlan::from_recipe(&recipe).map_err(CommandError::from)?;
    let scope = recipe_test_scope(&request, &plan).map_err(CommandError::from)?;
    let tls_pins = PinSet::from_strs(&request.tls_pin_sha256).map_err(CommandError::from)?;

    if let Some(conflict) = registry_web_rdp_conflict(ProfileProtocol::Web, &*state.connect_sessions.lock().await) {
        return Err(refuse_web_open("(recipe test)", conflict));
    }
    let token = crate::session::ssh::new_token();
    let window_label = format!("{WINDOW_LABEL_PREFIX}{token}");
    const TEST_TITLE: &str = "Recipe test";
    let shared = WebShared::new(TEST_TITLE, &display_origin(&scope.start_url));
    let data_dir = reserve_session(
        &state,
        &app,
        &token,
        WebSessionState {
            resource_name: TEST_TITLE.to_string(),
            profile_id: String::new(),
            window_label: window_label.clone(),
            data_dir: None,
            opened_at: Instant::now(),
            kind: WebSessionKind::RecipeTest,
            launch: None,
            shared: Arc::clone(&shared),
            relogin: None,
            engine: None,
        },
    )
    .await?;
    let cfg = web_session::WebSessionConfig {
        start_url: scope.start_url.clone(),
        origins: scope.origins.clone(),
        allow_insecure_http: scope.allow_insecure_http,
        allow_downloads: false,
        allow_popups: true,
        clipboard: WebClipboard::Off,
        width: DEFAULT_WINDOW_WIDTH,
        height: DEFAULT_WINDOW_HEIGHT,
        login: WebLogin::Open,
        tls_pins,
    };
    let gates = NativeGates {
        http_auth: None,
        tls_pin: (!cfg.tls_pins.is_empty()).then(|| {
            pin_gate(
                &app,
                &window_label,
                &shared,
                &cfg.tls_pins,
                &scope.origins,
                PinAudit { resource: TEST_TITLE.to_string(), token: token.clone(), launch_id_hash: None },
            )
        }),
    };
    let initial_url = if gates.is_empty() {
        scope.start_url.clone()
    } else {
        Url::parse("about:blank").map_err(|e| CommandError::from(format!("about:blank: {e}")))?
    };
    let win =
        match build_window(&app, &window_label, &token, TEST_TITLE, &cfg, &scope, &shared, data_dir, initial_url, None)
        {
            Ok(w) => w,
            Err(e) => {
                close_web_session(&state, &app, &token, WebCloseReason::WindowBuildFailed).await;
                return Err(e);
            }
        };
    hook_window_destroyed(&win.window, &app, &token);
    if !gates.is_empty() {
        if let Err(InstallError { check, reason }) = arm_native_handlers(&win.remote, gates, &scope.start_url).await {
            log::warn!(target: "audit", "connect.web.recipe_test: state=refused reason={check} token={token} — {reason}");
            close_web_session(&state, &app, &token, WebCloseReason::WindowBuildFailed).await;
            return Err(CommandError::from(format!(
                "this webview cannot honour the profile's TLS certificate pins ({reason}); the test window was closed"
            )));
        }
    }
    log::info!(
        target: "audit",
        "connect.web.recipe_test: state=started origins={} steps={} heuristic={} recipe_hash={hash} tls_pins={} \
         token={token}",
        scope.origins,
        plan.step_count(),
        plan.is_heuristic(),
        cfg.tls_pins.len(),
    );

    let page = TauriPage { app: app.clone(), label: window_label, shared };
    let report = run_check(&plan, &scope, &page, EngineTiming::for_plan(&plan)).await;
    log::info!(
        target: "audit",
        "connect.web.recipe_test: state=finished outcome={} steps_reached={} token={token}",
        report.outcome,
        report.steps.iter().filter(|s| s.reached).count(),
    );
    close_web_session(&state, &app, &token, WebCloseReason::SessionClose).await;
    Ok(WebRecipeTestResponse { recipe_hash: hash, report })
}

// ── The window ─────────────────────────────────────────────────────

/// Create this session's webview data directory under this process's
/// instance directory, sweeping instance directories of dead processes
/// first (see [`web_session::session_data_dir`]). `None` on macOS:
/// WKWebView ignores `data_directory`, and `incognito` already gives each
/// window its own non-persistent `WKWebsiteDataStore` (wry prefers it over
/// a `data_store_identifier`, so setting one would change nothing).
fn prepare_data_dir(app: &AppHandle, token: &str) -> CmdResult<Option<PathBuf>> {
    if cfg!(target_os = "macos") {
        return Ok(None);
    }
    let root = app
        .path()
        .app_cache_dir()
        .map_err(|e| CommandError::from(format!("resolve app cache dir for the web session: {e}")))?
        .join(DATA_DIR_NAME);
    web_session::session_data_dir(&root, token).map(Some).map_err(CommandError::from)
}

fn set_title_later(app: &AppHandle, label: &str, title: String) {
    // Window APIs are called from a task rather than from inside the
    // webview callback, so a callback that fires while the window is being
    // built can't re-enter the window registry.
    let app = app.clone();
    let label = label.to_string();
    tauri::async_runtime::spawn(async move {
        if let Some(w) = session_window(&app, &label) {
            let _ = w.set_title(&title);
        }
    });
}

/// The webview holding a session's remote content (label `web-<token>`):
/// navigation, the native handlers and the fill routine go here.
pub(crate) fn remote_webview(app: &AppHandle, label: &str) -> Option<tauri::Webview> {
    #[cfg(feature = "web_session_chrome")]
    {
        app.get_webview(label)
    }
    #[cfg(not(feature = "web_session_chrome"))]
    {
        app.get_webview_window(label).map(|w| AsRef::<tauri::Webview>::as_ref(&w).clone())
    }
}

/// A session's OS window (label `web-<token>`), which owns the title and
/// whose destruction tears the session down.
pub(crate) fn session_window(app: &AppHandle, label: &str) -> Option<tauri::Window> {
    #[cfg(feature = "web_session_chrome")]
    {
        app.get_window(label)
    }
    #[cfg(not(feature = "web_session_chrome"))]
    {
        app.get_webview_window(label).map(|w| AsRef::<tauri::Webview>::as_ref(&w).window())
    }
}

/// A built session window.
struct SessionWindow {
    window: tauri::Window,
    remote: tauri::Webview,
}

/// Everything the remote webview's handlers close over.
struct RemotePolicy {
    app: AppHandle,
    label: String,
    token: String,
    resource: String,
    origins: Arc<OriginSet>,
    shared: Arc<WebShared>,
}

impl RemotePolicy {
    /// Navigation allow-list.
    fn on_navigation(&self) -> impl Fn(&Url) -> bool + Send + 'static {
        let origins = Arc::clone(&self.origins);
        let shared = Arc::clone(&self.shared);
        let app = self.app.clone();
        let label = self.label.clone();
        let token = self.token.clone();
        let resource = self.resource.clone();
        move |url: &Url| -> bool {
            match origins.check(url) {
                NavigationVerdict::Allow => true,
                NavigationVerdict::Block { origin } => {
                    // Origin only: paths and queries can carry tokens.
                    log::info!(
                        target: "audit",
                        "connect.web.navigation_blocked: resource={resource} token={token} origin={origin}"
                    );
                    let title = shared.set_notice(format!("blocked: {origin}"));
                    set_title_later(&app, &label, title);
                    false
                }
            }
        }
    }

    /// New windows. Never `NewWindowResponse::Allow`: that hands the popup
    /// to the platform's default implementation, outside this window's
    /// handlers and data store. An in-set popup is instead loaded in this
    /// webview (same session store, same allow-list); everything else is
    /// denied.
    fn on_new_window(
        &self,
        allow_popups: bool,
    ) -> impl Fn(Url, tauri::webview::NewWindowFeatures) -> NewWindowResponse<tauri::Wry> + Send + Sync + 'static {
        let origins = Arc::clone(&self.origins);
        let app = self.app.clone();
        let label = self.label.clone();
        let token = self.token.clone();
        let resource = self.resource.clone();
        move |url: Url, _features: tauri::webview::NewWindowFeatures| {
            match origins.check_popup(&url, allow_popups) {
                NavigationVerdict::Allow => {
                    let app = app.clone();
                    let label = label.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Some(w) = remote_webview(&app, &label) {
                            let _ = w.navigate(url);
                        }
                    });
                }
                NavigationVerdict::Block { origin } => {
                    log::info!(
                        target: "audit",
                        "connect.web.popup_blocked: resource={resource} token={token} origin={origin}"
                    );
                }
            }
            NewWindowResponse::Deny
        }
    }

    /// Downloads. A handler is always installed: without one, WebView2 runs
    /// its own download UI. Denied unless the profile allows downloads and
    /// the download's origin is in the set; allowed downloads go to the
    /// webview's default destination and are audited by file name and size.
    fn on_download(
        &self,
        allow_downloads: bool,
    ) -> impl Fn(tauri::Webview, DownloadEvent<'_>) -> bool + Send + Sync + 'static {
        let origins = Arc::clone(&self.origins);
        let token = self.token.clone();
        let resource = self.resource.clone();
        move |_webview: tauri::Webview, event: DownloadEvent<'_>| -> bool {
            match event {
                DownloadEvent::Requested { url, destination } => {
                    let origin = display_origin(&url);
                    // An allowed download must also come from an origin the
                    // window may navigate to.
                    if let DownloadDecision::Deny { reason, origin } =
                        download_decision(allow_downloads, &origins, &url)
                    {
                        log::info!(
                            target: "audit",
                            "connect.web.download_blocked: resource={resource} token={token} origin={origin} \
                             reason={reason}"
                        );
                        return false;
                    }
                    log::info!(
                        target: "audit",
                        "connect.web.download: resource={resource} token={token} origin={origin} \
                         filename={} state=requested",
                        download_file_name(destination),
                    );
                    true
                }
                DownloadEvent::Finished { url, path, success } => {
                    if allow_downloads {
                        let size = path.as_deref().and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len());
                        log::info!(
                            target: "audit",
                            "connect.web.download: resource={resource} token={token} origin={} filename={} \
                             size={} success={success} state=finished",
                            display_origin(&url),
                            path.as_deref().map(download_file_name).unwrap_or_else(|| "(unreported)".to_string()),
                            size.map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()),
                        );
                    }
                    true
                }
                _ => false,
            }
        }
    }

    /// Host-observed page state. Returns the new title for the caller to
    /// set, or `None` when the load broke the policy and the session is being
    /// ended. `http_auth` hears every finished top-frame load.
    fn on_page_load(
        &self,
        http_auth: Option<Arc<HttpAuthGate>>,
    ) -> impl Fn(&Url, PageLoadEvent) -> Option<String> + Send + Sync + 'static {
        let origins = Arc::clone(&self.origins);
        let shared = Arc::clone(&self.shared);
        let app = self.app.clone();
        let label = self.label.clone();
        let token = self.token.clone();
        let resource = self.resource.clone();
        move |url: &Url, event: PageLoadEvent| {
            if let NavigationVerdict::Block { origin } = origins.check(url) {
                // A top-frame load the navigation handler should have
                // refused. Not expected on any platform; if it happens
                // anyway, the policy has been bypassed and the session ends
                // rather than carrying on outside its allow-list (a form
                // launch is closed with `aborted:policy_violation`).
                log::warn!(
                    target: "audit",
                    "connect.web.policy_violation: resource={resource} token={token} origin={origin} \
                     — closing the session"
                );
                shared.note_abort("policy_violation");
                let app = app.clone();
                let label = label.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(w) = session_window(&app, &label) {
                        let _ = w.destroy();
                    }
                });
                return None;
            }
            // The recipe engine reads the load state from here: steps run
            // only on a finished top-frame load the host saw.
            let finished = matches!(event, PageLoadEvent::Finished);
            let title = shared.page_load(url, finished);
            if let (true, Some(gate)) = (finished, &http_auth) {
                gate.page_finished(url);
            }
            Some(title)
        }
    }
}

/// Build the session window on `initial_url` (`scope.start_url`, or
/// `about:blank` for a window that navigates once its native handlers are
/// attached), navigating only within `scope.origins` — for a form or
/// http-auth launch, the server's scope.
///
/// Without `web_session_chrome` this is the single remote webview of
/// Phases 1–4. With it, the same remote webview sits below the vault-owned
/// toolbar ([`build_chrome_window`]).
#[allow(clippy::too_many_arguments)]
fn build_window(
    app: &AppHandle,
    label: &str,
    token: &str,
    resource: &str,
    cfg: &web_session::WebSessionConfig,
    scope: &EffectiveScope,
    shared: &Arc<WebShared>,
    data_dir: Option<PathBuf>,
    initial_url: Url,
    http_auth: Option<Arc<HttpAuthGate>>,
) -> CmdResult<SessionWindow> {
    let policy = RemotePolicy {
        app: app.clone(),
        label: label.to_string(),
        token: token.to_string(),
        resource: resource.to_string(),
        origins: Arc::new(scope.origins.clone()),
        shared: Arc::clone(shared),
    };
    let page_load = policy.on_page_load(http_auth);

    #[cfg(not(feature = "web_session_chrome"))]
    {
        let mut builder = WebviewWindowBuilder::new(app, label, WebviewUrl::External(initial_url))
            .title(shared.title())
            .inner_size(f64::from(cfg.width), f64::from(cfg.height))
            .resizable(true)
            .focused(true)
            .incognito(true)
            .devtools(false)
            // Tauri's drag-drop handler turns OS file drops into IPC events
            // carrying local paths. The page gets native HTML5 drops instead.
            .disable_drag_drop_handler()
            .on_navigation(policy.on_navigation())
            .on_new_window(policy.on_new_window(cfg.allow_popups))
            .on_download(policy.on_download(cfg.allow_downloads))
            .on_page_load(move |window: tauri::WebviewWindow, payload: tauri::webview::PageLoadPayload<'_>| {
                if let Some(title) = page_load(payload.url(), payload.event()) {
                    let _ = window.set_title(&title);
                }
            });
        if let Some(dir) = data_dir {
            builder = builder.data_directory(dir);
        }
        if cfg.clipboard.grants_page_clipboard_access() {
            builder = builder.enable_clipboard_access();
        }
        let win = builder.build().map_err(|e| CommandError::from(format!("spawn web session window: {e}")))?;
        let remote = AsRef::<tauri::Webview>::as_ref(&win).clone();
        Ok(SessionWindow { window: remote.window(), remote })
    }

    #[cfg(feature = "web_session_chrome")]
    {
        let mut remote = tauri::WebviewBuilder::new(label, WebviewUrl::External(initial_url))
            .focused(true)
            .incognito(true)
            .devtools(false)
            // Tauri's drag-drop handler turns OS file drops into IPC events
            // carrying local paths. The page gets native HTML5 drops instead.
            .disable_drag_drop_handler()
            .on_navigation(policy.on_navigation())
            .on_new_window(policy.on_new_window(cfg.allow_popups))
            .on_download(policy.on_download(cfg.allow_downloads))
            .on_page_load(move |webview: tauri::Webview, payload: tauri::webview::PageLoadPayload<'_>| {
                if let Some(title) = page_load(payload.url(), payload.event()) {
                    let _ = webview.window().set_title(&title);
                }
            });
        if let Some(dir) = data_dir {
            remote = remote.data_directory(dir);
        }
        if cfg.clipboard.grants_page_clipboard_access() {
            remote = remote.enable_clipboard_access();
        }
        super::connect_web_chrome::build_chrome_window(app, label, token, &shared.title(), cfg, remote)
            .map(|(window, remote)| SessionWindow { window, remote })
    }
}

#[cfg(test)]
mod transport_tests {
    use super::web_transport_refusal;

    #[test]
    fn rustion_required_refuses_and_never_falls_back() {
        let err = web_transport_refusal("rustion-required", None).unwrap();
        assert!(err.contains("rustion-required"), "{err}");
    }

    #[test]
    fn a_lock_violation_refuses_whatever_the_transport() {
        assert!(web_transport_refusal("direct", Some("tier locked")).unwrap().contains("lock violation"));
    }

    #[test]
    fn direct_preferred_and_unset_run_locally() {
        assert_eq!(web_transport_refusal("direct", None), None);
        assert_eq!(web_transport_refusal("rustion-preferred", None), None);
        assert_eq!(web_transport_refusal("", None), None);
    }
}

/// The web session window's isolation rests on two facts about the
/// capability set: no capability names a window or webview that a
/// `web-<token>` label matches, and no capability grants a remote origin
/// (Tauri gives a remote origin IPC only through a `remote` URL list). A
/// new capability, or a widened glob like `*`, breaks this test rather than
/// silently handing remote content the vault's command surface.
///
/// Phase 5 adds the session toolbar, a local webview labelled
/// `webchrome-<token>` in the same `web-<token>` window. It needs no
/// capability (it calls app commands only), so none may reach it either:
/// its plugin surface — events, windows, webview creation — stays empty.
/// Tauri resolves a capability by window label *or* webview label, which
/// is why a `windows` glob matching `web-<token>` would reach both webviews
/// of the window, and why the remote webview keeps the window's label.
#[cfg(test)]
mod capability_isolation_tests {
    use serde_json::Value;
    use std::path::{Path, PathBuf};

    /// Labels a web session window, its remote webview and its toolbar
    /// webview can take: `web-` / `webchrome-` + `sess_<32 hex>`.
    const SAMPLE_LABELS: &[&str] = &[
        "web-sess_0123456789abcdef0123456789abcdef",
        "web-x",
        "web-",
        "webchrome-sess_0123456789abcdef0123456789abcdef",
        "webchrome-x",
        "webchrome-",
    ];

    #[test]
    fn the_samples_cover_the_labels_the_host_builds() {
        let token = "sess_0123456789abcdef0123456789abcdef";
        let window = format!("{}{token}", crate::session::web::WINDOW_LABEL_PREFIX);
        let chrome = crate::session::web_chrome::chrome_label(token);
        assert!(SAMPLE_LABELS.contains(&window.as_str()), "{window}");
        assert!(SAMPLE_LABELS.contains(&chrome.as_str()), "{chrome}");
    }

    /// Tauri matches window/webview labels with `glob::Pattern`. This covers
    /// `*` and `?`; any other metacharacter fails the test so it gets
    /// extended rather than quietly mis-evaluated.
    fn glob_match(pattern: &str, label: &str) -> bool {
        fn rec(p: &[char], l: &[char]) -> bool {
            match p.first() {
                None => l.is_empty(),
                Some('*') => (0..=l.len()).any(|i| rec(&p[1..], &l[i..])),
                Some('?') => !l.is_empty() && rec(&p[1..], &l[1..]),
                Some(c) => l.first() == Some(c) && rec(&p[1..], &l[1..]),
            }
        }
        let p: Vec<char> = pattern.chars().collect();
        let l: Vec<char> = label.chars().collect();
        rec(&p, &l)
    }

    fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files_under(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    fn check_capability(source: &str, cap: &Value) {
        let obj = cap.as_object().unwrap_or_else(|| panic!("{source}: capability is not an object"));
        assert!(
            !obj.contains_key("remote"),
            "{source}: declares a `remote` URL list — remote origins must never be granted IPC"
        );
        for key in ["windows", "webviews"] {
            let Some(list) = obj.get(key) else { continue };
            let list = list.as_array().unwrap_or_else(|| panic!("{source}: `{key}` is not an array"));
            for pattern in list {
                let pattern = pattern.as_str().unwrap_or_else(|| panic!("{source}: non-string `{key}` entry"));
                assert!(
                    !pattern.contains(['[', ']', '{', '}', '\\', '!']),
                    "{source}: `{key}` pattern `{pattern}` uses glob syntax this test can't evaluate — extend \
                     `glob_match` before adding it"
                );
                for label in SAMPLE_LABELS {
                    assert!(
                        !glob_match(pattern, label),
                        "{source}: `{key}` pattern `{pattern}` matches web session label `{label}`"
                    );
                }
            }
        }
    }

    #[test]
    fn glob_matcher_self_test() {
        assert!(glob_match("*", "web-x"));
        assert!(glob_match("web-*", "web-sess_ab"));
        assert!(glob_match("w?b-*", "web-x"));
        assert!(glob_match("*-*", "web-x"));
        assert!(!glob_match("ssh-*", "web-x"));
        assert!(!glob_match("main", "web-x"));
        assert!(!glob_match("plugin-*", "web-x"));
    }

    #[test]
    fn no_capability_file_reaches_web_session_windows() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
        let mut files = Vec::new();
        files_under(&dir, &mut files);
        assert!(!files.is_empty(), "no capability files found under {}", dir.display());
        for file in files {
            let source = file.display().to_string();
            // tauri-build also reads TOML capabilities; only JSON exists today
            // and anything else must be added to this test first.
            assert_eq!(
                file.extension().and_then(|e| e.to_str()),
                Some("json"),
                "{source}: non-JSON capability file — teach this test to parse it"
            );
            let text = std::fs::read_to_string(&file).unwrap();
            let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{source}: {e}"));
            // A file may hold one capability or a `capabilities` list.
            match value.get("capabilities").and_then(|c| c.as_array()) {
                Some(list) => list.iter().for_each(|c| check_capability(&source, c)),
                None => check_capability(&source, &value),
            }
        }
    }

    #[test]
    fn no_inline_capability_in_tauri_conf_reaches_web_session_windows() {
        let conf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json");
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&conf).unwrap()).unwrap();
        let inline = value.pointer("/app/security/capabilities").and_then(|c| c.as_array());
        for cap in inline.into_iter().flatten() {
            // A string is a reference to a capability file, checked above.
            if cap.is_object() {
                check_capability("tauri.conf.json app.security.capabilities", cap);
            }
        }
    }

    #[test]
    fn the_shipped_window_globs_do_not_match_web_labels() {
        for pattern in ["main", "ssh-*", "rdp-*", "plugin-*"] {
            for label in SAMPLE_LABELS {
                assert!(!glob_match(pattern, label), "{pattern} vs {label}");
            }
        }
    }
}
