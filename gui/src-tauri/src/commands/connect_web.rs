//! `session_open_web` — Web Application Connect, Phase 1
//! (features/web-application-connect.md §4, T96).
//!
//! Opens an ephemeral BastionVault window on a `web` connection profile's
//! start URL. Phase 1 supports `login_mode: "open"` only: no credential is
//! resolved, read or released — the window is an audited, policy-bound
//! launch point for applications that do their own login (typically SSO).
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
//! * a host-owned window title (`<resource> — <origin>`), never
//!   `document.title`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tauri::webview::{DownloadEvent, NewWindowResponse, PageLoadEvent};
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder};

use super::connect::{
    collect_policy_hints, find_profile, read_effective_policy, read_resource_meta, record_recent_session,
    SessionProtocolTag,
};
use crate::error::{CmdResult, CommandError};
use crate::session::web::{
    self as web_session, display_origin, download_file_name, NavigationVerdict, WebSessionState, DATA_DIR_NAME,
    WINDOW_LABEL_PREFIX,
};
use crate::session::{ProfileProtocol, SessionState};
use crate::state::AppState;

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

    // Transport policy before the MFA pre-flight, so a refusal here doesn't
    // burn the operator's connect ticket.
    let (resource_id, resource_type, asset_group_ids) =
        collect_policy_hints(&state, &request.resource_name, &meta).await;
    let effective = read_effective_policy(&state, &resource_id, &resource_type, &asset_group_ids).await?;
    if let Some(reason) = web_transport_refusal(&effective.transport, effective.lock_violation.as_deref()) {
        return Err(CommandError::from(reason));
    }

    // Same server-side pre-flight as a direct SSH/RDP dial: checks the
    // `connect` grant and, on a `require_mfa` profile, verifies and burns
    // the ticket. Nothing is opened until it says yes.
    crate::commands::connect_mfa::authorize_direct(
        &state,
        &request.resource_name,
        &request.profile_id,
        request.connect_ticket.as_deref(),
    )
    .await?;

    let token = crate::session::ssh::new_token();
    let window_label = format!("{WINDOW_LABEL_PREFIX}{token}");
    let data_dir = prepare_data_dir(&state, &app, &token).await?;

    // Register before the window exists, so a window that closes the instant
    // it opens still finds its entry to tear down.
    state.connect_sessions.lock().await.insert(
        token.clone(),
        SessionState::Web(WebSessionState {
            resource_name: request.resource_name.clone(),
            profile_id: request.profile_id.clone(),
            window_label: window_label.clone(),
            data_dir: data_dir.clone(),
            opened_at: Instant::now(),
        }),
    );

    let win = match build_window(&app, &window_label, &token, &request.resource_name, &cfg, data_dir) {
        Ok(w) => w,
        Err(e) => {
            close_web_session(&state, &app, &token, "window-build-failed").await;
            return Err(e);
        }
    };

    let token_for_destroy = token.clone();
    let app_for_destroy = app.clone();
    win.on_window_event(move |ev| {
        if let tauri::WindowEvent::Destroyed = ev {
            let token = token_for_destroy.clone();
            let app = app_for_destroy.clone();
            tauri::async_runtime::spawn(async move {
                let s = app.state::<AppState>();
                close_web_session(&s, &app, &token, "window-closed").await;
            });
        }
    });

    let start_origin = display_origin(&cfg.start_url);
    log::info!(
        target: "audit",
        "session.open: protocol=web login_mode=open resource={} profile={} origin={} allowed_origins={} \
         downloads={} popups={} clipboard={:?} token={}",
        request.resource_name,
        request.profile_id,
        start_origin,
        cfg.origins,
        cfg.allow_downloads,
        cfg.allow_popups,
        cfg.clipboard,
        token,
    );

    let _ = record_recent_session(&state, &request.resource_name, &profile, SessionProtocolTag::Web).await;

    Ok(WebOpenResponse { token, window_label })
}

/// Tear down a web session: drop its registry entry, destroy its window,
/// write the close audit line and remove its data directory. Returns
/// `false` when `token` doesn't name a live web session (so the caller can
/// try the SSH/RDP paths). Idempotent: the window-destroyed hook and an
/// explicit `session_close` can both call it.
pub(crate) async fn close_web_session(state: &AppState, app: &AppHandle, token: &str, reason: &str) -> bool {
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
    if let Some(win) = app.get_webview_window(&session.window_label) {
        let _ = win.destroy();
    }
    web_session::finish_session(token, session, reason);
    true
}

/// Create this session's webview data directory, after sweeping any left
/// behind by sessions that are no longer live. `None` on macOS: WKWebView
/// ignores `data_directory`, and `incognito` already gives each window its
/// own non-persistent `WKWebsiteDataStore` (wry prefers it over a
/// `data_store_identifier`, so setting one would change nothing).
async fn prepare_data_dir(state: &AppState, app: &AppHandle, token: &str) -> CmdResult<Option<PathBuf>> {
    if cfg!(target_os = "macos") {
        return Ok(None);
    }
    let root = app
        .path()
        .app_cache_dir()
        .map_err(|e| CommandError::from(format!("resolve app cache dir for the web session: {e}")))?
        .join(DATA_DIR_NAME);
    let live: Vec<String> = state
        .connect_sessions
        .lock()
        .await
        .iter()
        .filter(|(_, s)| matches!(s, SessionState::Web(_)))
        .map(|(t, _)| t.clone())
        .collect();
    web_session::sweep_stale_data_dirs(&root, &live);

    let dir = root.join(token);
    std::fs::create_dir_all(&dir)
        .map_err(|e| CommandError::from(format!("create web session data dir {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| CommandError::from(format!("restrict web session data dir {}: {e}", dir.display())))?;
    }
    Ok(Some(dir))
}

fn set_title_later(app: &AppHandle, label: &str, title: String) {
    // Window APIs are called from a task rather than from inside the
    // webview callback, so a callback that fires while the window is being
    // built can't re-enter the window registry.
    let app = app.clone();
    let label = label.to_string();
    tauri::async_runtime::spawn(async move {
        if let Some(w) = app.get_webview_window(&label) {
            let _ = w.set_title(&title);
        }
    });
}

fn build_window(
    app: &AppHandle,
    label: &str,
    token: &str,
    resource: &str,
    cfg: &web_session::WebSessionConfig,
    data_dir: Option<PathBuf>,
) -> CmdResult<tauri::WebviewWindow> {
    let origins = Arc::new(cfg.origins.clone());
    // Last origin the host saw load in the top frame — the "current origin"
    // half of the title while a block notice is shown.
    let current_origin = Arc::new(Mutex::new(display_origin(&cfg.start_url)));

    // ── Navigation allow-list ──────────────────────────────────────
    let nav_origins = Arc::clone(&origins);
    let nav_current = Arc::clone(&current_origin);
    let nav_app = app.clone();
    let nav_label = label.to_string();
    let nav_token = token.to_string();
    let nav_resource = resource.to_string();
    let on_navigation = move |url: &tauri::Url| -> bool {
        match nav_origins.check(url) {
            NavigationVerdict::Allow => true,
            NavigationVerdict::Block { origin } => {
                // Origin only: paths and queries can carry tokens.
                log::info!(
                    target: "audit",
                    "connect.web.navigation_blocked: resource={nav_resource} token={nav_token} origin={origin}"
                );
                let current = nav_current.lock().map(|g| g.clone()).unwrap_or_default();
                set_title_later(&nav_app, &nav_label, format!("{nav_resource} — {current} — blocked: {origin}"));
                false
            }
        }
    };

    // ── New windows ───────────────────────────────────────────────
    // Never `NewWindowResponse::Allow`: that hands the popup to the
    // platform's default implementation, outside this window's handlers
    // and data store. An in-set popup is instead loaded in this window
    // (same session store, same allow-list); everything else is denied.
    let popup_origins = Arc::clone(&origins);
    let allow_popups = cfg.allow_popups;
    let popup_app = app.clone();
    let popup_label = label.to_string();
    let popup_token = token.to_string();
    let popup_resource = resource.to_string();
    let on_new_window = move |url: tauri::Url, _features: tauri::webview::NewWindowFeatures| {
        match popup_origins.check_popup(&url, allow_popups) {
            NavigationVerdict::Allow => {
                let app = popup_app.clone();
                let label = popup_label.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(w) = app.get_webview_window(&label) {
                        let _ = w.navigate(url);
                    }
                });
            }
            NavigationVerdict::Block { origin } => {
                log::info!(
                    target: "audit",
                    "connect.web.popup_blocked: resource={popup_resource} token={popup_token} origin={origin}"
                );
            }
        }
        NewWindowResponse::Deny
    };

    // ── Downloads ─────────────────────────────────────────────────
    // A handler is always installed: without one, WebView2 runs its own
    // download UI. Denied unless the profile allows downloads; allowed
    // downloads go to the webview's default destination and are audited by
    // file name and size.
    let allow_downloads = cfg.allow_downloads;
    let dl_token = token.to_string();
    let dl_resource = resource.to_string();
    let on_download = move |_webview: tauri::Webview, event: DownloadEvent<'_>| -> bool {
        match event {
            DownloadEvent::Requested { url, destination } => {
                let origin = display_origin(&url);
                if !allow_downloads {
                    log::info!(
                        target: "audit",
                        "connect.web.download_blocked: resource={dl_resource} token={dl_token} origin={origin}"
                    );
                    return false;
                }
                log::info!(
                    target: "audit",
                    "connect.web.download: resource={dl_resource} token={dl_token} origin={origin} \
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
                        "connect.web.download: resource={dl_resource} token={dl_token} origin={} filename={} \
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
    };

    // ── Host-owned title ──────────────────────────────────────────
    let load_origins = Arc::clone(&origins);
    let load_current = Arc::clone(&current_origin);
    let load_app = app.clone();
    let load_label = label.to_string();
    let load_token = token.to_string();
    let load_resource = resource.to_string();
    let on_page_load = move |window: tauri::WebviewWindow, payload: tauri::webview::PageLoadPayload<'_>| {
        let url = payload.url();
        if let NavigationVerdict::Block { origin } = load_origins.check(url) {
            // A top-frame load the navigation handler should have refused.
            // Not expected on any platform; if it happens anyway, the
            // policy has been bypassed and the session ends rather than
            // carrying on outside its allow-list.
            log::warn!(
                target: "audit",
                "connect.web.policy_violation: resource={load_resource} token={load_token} origin={origin} \
                 — closing the session"
            );
            let app = load_app.clone();
            let label = load_label.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(w) = app.get_webview_window(&label) {
                    let _ = w.destroy();
                }
            });
            return;
        }
        if matches!(payload.event(), PageLoadEvent::Started | PageLoadEvent::Finished) {
            let origin = display_origin(url);
            if let Ok(mut g) = load_current.lock() {
                *g = origin.clone();
            }
            let _ = window.set_title(&format!("{load_resource} — {origin}"));
        }
    };

    let mut builder = WebviewWindowBuilder::new(app, label, WebviewUrl::External(cfg.start_url.clone()))
        .title(format!("{resource} — {}", display_origin(&cfg.start_url)))
        .inner_size(f64::from(cfg.width), f64::from(cfg.height))
        .resizable(true)
        .focused(true)
        .incognito(true)
        .devtools(false)
        // Tauri's drag-drop handler turns OS file drops into IPC events
        // carrying local paths. The page gets native HTML5 drops instead.
        .disable_drag_drop_handler()
        .on_navigation(on_navigation)
        .on_new_window(on_new_window)
        .on_download(on_download)
        .on_page_load(on_page_load);
    if let Some(dir) = data_dir {
        builder = builder.data_directory(dir);
    }
    if cfg.clipboard.grants_page_clipboard_access() {
        builder = builder.enable_clipboard_access();
    }
    builder.build().map_err(|e| CommandError::from(format!("spawn web session window: {e}")))
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
#[cfg(test)]
mod capability_isolation_tests {
    use serde_json::Value;
    use std::path::{Path, PathBuf};

    /// Labels a web session window can take: `web-` + `sess_<32 hex>`.
    const SAMPLE_LABELS: &[&str] = &["web-sess_0123456789abcdef0123456789abcdef", "web-x", "web-"];

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
