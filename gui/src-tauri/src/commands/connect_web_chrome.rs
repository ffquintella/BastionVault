//! The web session toolbar ("session chrome") — features/web-application-connect.md
//! Phase 5, T96. Decisions live in `session::web_chrome` (Tauri-free, tested).
//!
//! A vault-owned strip above the remote content: the host-observed origin,
//! a lock indicator, the sign-in state and the time left in the sign-in
//! window, **Disconnect** and **Re-run login**. It is a second webview in
//! the session's window — never a script in the remote page, never the same
//! realm — so the page can neither read nor draw over it.
//!
//! * **Build feature.** The two-webview window needs Tauri's `unstable`
//!   multi-webview API, enabled by this crate's `web_session_chrome`
//!   feature (off by default — see the manifest for why). Without it,
//!   [`build_chrome_window`] is not compiled and a web session is the single
//!   remote webview of Phases 1–4; the commands below are still registered
//!   and refuse every caller, because no toolbar webview exists.
//! * **Three commands, no plugin permission.** The toolbar calls only the
//!   three app commands here. Since T110 the app has an ACL manifest, so a
//!   webview may call an app command only when a capability grants it: the
//!   toolbar's one capability (`capabilities/web-chrome-toolbar.json`,
//!   matched by webview label) grants exactly these three.
//!   `capability_isolation_tests` asserts no other capability reaches
//!   `webchrome-*` and that this one carries no plugin permission, so the
//!   toolbar cannot listen to events, create webviews or touch windows. It
//!   polls its state instead of subscribing.
//! * **Caller binding.** Each command takes the calling webview and maps it
//!   to a session with [`chrome_caller`] (toolbar label *and* hosting
//!   window), never from an argument.
//! * **Navigation.** The toolbar may load only the bundled page
//!   ([`chrome_navigation_allowed`]); new windows and downloads are refused.
//!   devtools are off, it has its own (incognito) store.

use std::time::Instant;

use tauri::{AppHandle, State};

use crate::error::{CmdResult, CommandError};
use crate::session::web::WebCloseReason;
use crate::session::web_chrome::{chrome_caller, chrome_state, ChromeState};
use crate::session::SessionState;
use crate::state::AppState;

/// The session token of the toolbar that is calling, or a refusal.
fn caller_token(webview: &tauri::Webview) -> CmdResult<String> {
    let window = webview.window();
    chrome_caller(webview.label(), window.label())
        .map(str::to_string)
        .map_err(|reason| CommandError::from(reason.to_string()))
}

/// What the toolbar renders, for the session it sits in.
#[tauri::command]
pub async fn web_chrome_state(state: State<'_, AppState>, webview: tauri::Webview) -> CmdResult<ChromeState> {
    let token = caller_token(&webview)?;
    let sessions = state.connect_sessions.lock().await;
    match sessions.get(&token) {
        Some(SessionState::Web(w)) => Ok(chrome_state(w, Instant::now())),
        _ => Err(CommandError::from("this web session has ended".to_string())),
    }
}

/// **Disconnect**: the same teardown as closing the window (`web/close`, the
/// data directory, `session.close: … reason=disconnect`).
#[tauri::command]
pub async fn web_chrome_disconnect(
    state: State<'_, AppState>,
    app: AppHandle,
    webview: tauri::Webview,
) -> CmdResult<()> {
    let token = caller_token(&webview)?;
    log::info!(target: "audit", "connect.web.chrome_disconnect: token={token}");
    super::connect_web::close_web_session(&state, &app, &token, WebCloseReason::Disconnect).await;
    Ok(())
}

/// **Re-run login**: a new launch and a fresh credential, `form` sessions
/// only (`connect_web::relogin_web_session`).
#[tauri::command]
pub async fn web_chrome_relogin(state: State<'_, AppState>, app: AppHandle, webview: tauri::Webview) -> CmdResult<()> {
    let token = caller_token(&webview)?;
    super::connect_web::relogin_web_session(&state, &app, &token).await
}

/// Build the two-webview session window: the toolbar on top, `remote` (the
/// fully configured remote-content webview, labelled like the window) below.
/// The window is sized so the remote area keeps the profile's size.
#[cfg(feature = "web_session_chrome")]
pub(super) fn build_chrome_window(
    app: &AppHandle,
    label: &str,
    token: &str,
    title: &str,
    cfg: &crate::session::web::WebSessionConfig,
    remote: tauri::WebviewBuilder<tauri::Wry>,
) -> CmdResult<(tauri::Window, tauri::Webview)> {
    use tauri::webview::NewWindowResponse;
    use tauri::{LogicalPosition, LogicalSize, WebviewBuilder, WebviewUrl, WindowBuilder};

    use crate::session::web_chrome::{chrome_label, chrome_navigation_allowed, layout, CHROME_HEIGHT, CHROME_PAGE};

    let width = f64::from(cfg.width);
    let height = f64::from(cfg.height) + CHROME_HEIGHT;
    let window = WindowBuilder::new(app, label)
        .title(title)
        .inner_size(width, height)
        .resizable(true)
        .focused(true)
        .build()
        .map_err(|e| CommandError::from(format!("spawn web session window: {e}")))?;

    let chrome_label = chrome_label(token);
    // The dev server's origin is accepted in debug builds only, where
    // `WebviewUrl::App` resolves to it.
    let dev_url = if cfg!(debug_assertions) { app.config().build.dev_url.clone() } else { None };
    let nav_token = token.to_string();
    let toolbar = WebviewBuilder::new(&chrome_label, WebviewUrl::App(CHROME_PAGE.into()))
        .incognito(true)
        .devtools(false)
        .disable_drag_drop_handler()
        .on_navigation(move |url| {
            let allowed = chrome_navigation_allowed(url, dev_url.as_ref());
            if !allowed {
                log::warn!(
                    target: "audit",
                    "connect.web.chrome_navigation_blocked: token={nav_token} origin={}",
                    crate::session::web::display_origin(url)
                );
            }
            allowed
        })
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .on_download(|_, _| false);

    let (bar, content) = layout(width, height);
    let built = window
        .add_child(toolbar, LogicalPosition::new(bar.x, bar.y), LogicalSize::new(bar.width, bar.height))
        .and_then(|toolbar| {
            window
                .add_child(
                    remote,
                    LogicalPosition::new(content.x, content.y),
                    LogicalSize::new(content.width, content.height),
                )
                .map(|remote| (toolbar, remote))
        });
    let (toolbar, remote) = match built {
        Ok(pair) => pair,
        Err(e) => {
            let _ = window.destroy();
            return Err(CommandError::from(format!("spawn web session window: {e}")));
        }
    };

    // Keep the toolbar a fixed strip on resize. Bounds are applied from a
    // task, not inside the window-event callback, so the runtime is never
    // re-entered while it dispatches the event.
    let resize_window = window.clone();
    let (resize_toolbar, resize_remote) = (toolbar, remote.clone());
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::Resized(size) = event {
            let scale = resize_window.scale_factor().unwrap_or(1.0);
            let logical = size.to_logical::<f64>(scale);
            let (bar, content) = layout(logical.width, logical.height);
            let toolbar = resize_toolbar.clone();
            let remote = resize_remote.clone();
            tauri::async_runtime::spawn(async move {
                let _ = toolbar.set_position(LogicalPosition::new(bar.x, bar.y));
                let _ = toolbar.set_size(LogicalSize::new(bar.width, bar.height));
                let _ = remote.set_position(LogicalPosition::new(content.x, content.y));
                let _ = remote.set_size(LogicalSize::new(content.width, content.height));
            });
        }
    });

    // A child webview is not made the first responder on macOS; give the
    // keyboard to the application, as the single-webview window did.
    let _ = remote.set_focus();
    Ok((window, remote))
}
