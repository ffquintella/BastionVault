//! Web session chrome — the vault-owned toolbar beside a web session's remote
//! webview (features/web-application-connect.md §4 and Phase 5, T96).
//!
//! The parts that need no Tauri runtime, so they can be unit-tested: the
//! toolbar's label and how a caller is mapped back to its session, the
//! window layout, the toolbar's navigation rule, the lock indicator, the
//! sign-in window countdown and the re-run decision, and the state the
//! toolbar renders. The commands live in `commands/connect_web_chrome.rs`;
//! the window is built in `commands/connect_web.rs`.
//!
//! The isolation model, which this module must never weaken:
//!
//! * The remote content keeps its own webview, labelled `web-<token>`, in a
//!   window labelled `web-<token>` — the labels no capability matches
//!   (`capability_isolation_tests`). It never shares a realm with the
//!   toolbar.
//! * The toolbar is a second webview in that window, labelled
//!   `webchrome-<token>`, loading only the bundled `web-chrome.html`. Its one
//!   capability (`capabilities/web-chrome-toolbar.json`, matched by webview
//!   label) grants the three app commands it calls and nothing else — the
//!   app has an ACL manifest since T110, so without it the toolbar could
//!   call nothing. The capability test asserts no other capability reaches
//!   it and that this one carries no plugin permission, so its plugin
//!   surface stays empty.
//! * The commands derive the session from the calling webview's label *and*
//!   the label of the window hosting it ([`chrome_caller`]), never from an
//!   argument, so a toolbar can only act on the session it sits in and no
//!   other webview can act on any session through them.
//! * Nothing here uses a `tauri::ipc::Channel`, so the web/RDP exclusion
//!   predicate (T98) is unchanged.

use std::time::Instant;

use serde::Serialize;
use tauri::Url;

use super::web::{WebOrigin, WebSessionKind, WebSessionState, WINDOW_LABEL_PREFIX};

/// Prefix of every web session toolbar webview label. Must not be matched by
/// `web-*` (the remote content's prefix) nor match it — asserted below and
/// by `capability_isolation_tests`.
pub const CHROME_LABEL_PREFIX: &str = "webchrome-";

/// The toolbar's page, bundled with the frontend (`gui/web-chrome.html`).
#[cfg_attr(not(feature = "web_session_chrome"), allow(dead_code))] // window builder only; tested in every build
pub const CHROME_PAGE: &str = "web-chrome.html";

/// Toolbar height in logical pixels. The remote webview gets the rest.
#[cfg_attr(not(feature = "web_session_chrome"), allow(dead_code))] // window builder only; tested in every build
pub const CHROME_HEIGHT: f64 = 40.0;

/// Session tokens are `sess_` + 32 lowercase hex (`session::ssh::new_token`).
fn is_session_token(token: &str) -> bool {
    token
        .strip_prefix("sess_")
        .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// The toolbar webview label of the session `token`.
#[cfg_attr(not(feature = "web_session_chrome"), allow(dead_code))] // window builder only; tested in every build
pub fn chrome_label(token: &str) -> String {
    format!("{CHROME_LABEL_PREFIX}{token}")
}

/// Why a caller of a toolbar command was refused. Fixed text, safe to show.
pub const NOT_A_CHROME: &str = "only a web session's own toolbar can use this command";

/// Map the caller of a toolbar command back to its session token.
///
/// The webview must carry a toolbar label for a well-formed token **and**
/// sit in that same session's window (`web-<token>`). The main window, an
/// SSH or RDP window, and the remote content itself (`web-<token>`) are all
/// refused, as is a toolbar label hosted anywhere else.
pub fn chrome_caller<'a>(webview_label: &'a str, window_label: &str) -> Result<&'a str, &'static str> {
    let token = webview_label.strip_prefix(CHROME_LABEL_PREFIX).filter(|t| is_session_token(t)).ok_or(NOT_A_CHROME)?;
    match window_label.strip_prefix(WINDOW_LABEL_PREFIX) {
        Some(w) if w == token => Ok(token),
        _ => Err(NOT_A_CHROME),
    }
}

/// A rectangle in logical pixels, origin top-left.
#[cfg_attr(not(feature = "web_session_chrome"), allow(dead_code))] // window builder only; tested in every build
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Split a window's logical inner size into `(toolbar, remote)`: the toolbar
/// is a fixed-height strip across the top, the remote content everything
/// below it. They never overlap, so the page cannot draw over the toolbar.
#[cfg_attr(not(feature = "web_session_chrome"), allow(dead_code))] // window builder only; tested in every build
pub fn layout(width: f64, height: f64) -> (Bounds, Bounds) {
    let width = if width.is_finite() { width.max(0.0) } else { 0.0 };
    let height = if height.is_finite() { height.max(0.0) } else { 0.0 };
    let bar = CHROME_HEIGHT.min(height);
    (Bounds { x: 0.0, y: 0.0, width, height: bar }, Bounds { x: 0.0, y: bar, width, height: height - bar })
}

/// Whether the toolbar webview may load `url`: only the bundled toolbar page,
/// from the app's own asset origin — `tauri://localhost` (macOS, Linux) or
/// `http(s)://tauri.localhost` (Windows) — or, in a debug build, the dev
/// server's origin. Anything else (a link, a redirect, a script-driven
/// navigation) is refused, so the toolbar can never become remote content.
#[cfg_attr(not(feature = "web_session_chrome"), allow(dead_code))] // window builder only; tested in every build
pub fn chrome_navigation_allowed(url: &Url, dev_url: Option<&Url>) -> bool {
    if !url.username().is_empty() || url.password().is_some() || url.path() != format!("/{CHROME_PAGE}") {
        return false;
    }
    let host = url.host_str().unwrap_or("");
    let app_asset = matches!((url.scheme(), host), ("tauri", "localhost") | ("http" | "https", "tauri.localhost"))
        && url.port().is_none();
    let dev = dev_url.is_some_and(|d| {
        d.scheme() == url.scheme()
            && d.host_str() == url.host_str()
            && d.port_or_known_default() == url.port_or_known_default()
    });
    app_asset || dev
}

/// The toolbar's lock indicator for the page the host observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LockState {
    /// No http(s) page yet (`about:blank` while handlers attach).
    None,
    /// https, certificate accepted by the platform.
    Secure,
    /// https, certificate the platform rejected and a profile pin accepted.
    Pinned,
    /// Plain http (`allow_insecure_http`).
    Insecure,
}

/// Decide the lock indicator. `accepted_on_pin` answers whether this session
/// accepted a certificate for an origin on a pin (`TlsPinGate`).
pub fn lock_state(url: Option<&Url>, accepted_on_pin: impl Fn(&WebOrigin) -> bool) -> LockState {
    let Some(url) = url else { return LockState::None };
    match url.scheme() {
        "http" => LockState::Insecure,
        "https" => match WebOrigin::of_url(url) {
            Some(o) if accepted_on_pin(&o) => LockState::Pinned,
            _ => LockState::Secure,
        },
        _ => LockState::None,
    }
}

/// Whether the toolbar's **Re-run login** applies to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relogin {
    Available,
    Running,
    Unavailable(&'static str),
}

/// Re-run is offered for `form` sessions only. It always goes through a new
/// `launch` (new `launch_id`, server-side authorisation, audit) and a fresh
/// credential; nothing is replayed.
///
/// * `http-auth`: the webview keeps the answered credential for the window's
///   lifetime and the handler answers once per (origin, realm), so a re-run
///   could not take effect without rebuilding the window.
/// * `open`: releases no credential; the application signs in by itself.
/// * a recipe test holds no credential at all.
/// * a `form` session signed in with a credential-provider account
///   (`credential_provider`): the provider releases an account again only
///   after a fresh connect-time MFA check, which the toolbar cannot run (its
///   webview is granted three commands, none of them a factor ceremony), so a
///   re-run would only be refused with `mfa_required` and leave a denied
///   audit line. Connecting again runs the picker and the check.
pub fn relogin_availability(kind: WebSessionKind, credential_provider: bool, running: bool) -> Relogin {
    match kind {
        WebSessionKind::Form if credential_provider => Relogin::Unavailable(
            "this session signed in with an account from a credential provider, which is released again only \
             after a new connect-time MFA check; disconnect and connect again to sign in afresh",
        ),
        WebSessionKind::Form if running => Relogin::Running,
        WebSessionKind::Form => Relogin::Available,
        WebSessionKind::HttpAuth => Relogin::Unavailable(
            "HTTP authentication is answered once per window; disconnect and connect again to sign in afresh",
        ),
        WebSessionKind::Open => {
            Relogin::Unavailable("this profile releases no credential; the application signs in by itself")
        }
        WebSessionKind::RecipeTest => Relogin::Unavailable("a recipe test holds no credential"),
    }
}

/// Whole seconds left until `deadline`, rounded up; `None` once it has
/// passed or when there is none.
pub fn remaining_secs(now: Instant, deadline: Option<Instant>) -> Option<u64> {
    let left = deadline?.checked_duration_since(now)?;
    if left.is_zero() {
        return None;
    }
    Some(left.as_secs() + u64::from(left.subsec_nanos() > 0))
}

/// What the toolbar renders. Every field is host-observed or host-decided;
/// nothing comes from the page. Never a URL path, a query or a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChromeState {
    pub resource: String,
    /// Origin of the top-frame page the host last saw loading.
    pub origin: String,
    pub lock: LockState,
    /// `blocked: <origin>` and similar, as in the window title.
    pub notice: Option<String>,
    /// The sign-in state, as in the window title.
    pub login: Option<String>,
    /// `open`, `form`, `http-auth` or `recipe_test`.
    pub login_mode: &'static str,
    /// Seconds left in the sign-in window — how long the host may still hold
    /// a released credential (the recipe's `timeout_secs`, or the http-auth
    /// answer window). `None` when no credential is held.
    pub login_window_secs: Option<u64>,
    /// Seconds since the session opened.
    pub elapsed_secs: u64,
    /// `available`, `running` or `unavailable`.
    pub relogin: &'static str,
    pub relogin_reason: Option<&'static str>,
}

/// Assemble the toolbar state of one registry entry at `now`.
pub fn chrome_state(session: &WebSessionState, now: Instant) -> ChromeState {
    let shared = &session.shared;
    let view = shared.chrome_view();
    let lock = lock_state(view.url.as_ref(), |o| shared.accepted_on_pin(o));
    let (relogin, relogin_reason) =
        match relogin_availability(session.kind, session.credential_provider, shared.relogin_running()) {
            Relogin::Available => ("available", None),
            Relogin::Running => ("running", None),
            Relogin::Unavailable(reason) => ("unavailable", Some(reason)),
        };
    ChromeState {
        resource: session.resource_name.clone(),
        origin: view.origin,
        lock,
        notice: view.notice,
        login: view.login,
        login_mode: session.kind.as_str(),
        login_window_secs: remaining_secs(now, view.login_deadline),
        elapsed_secs: now.saturating_duration_since(session.opened_at).as_secs(),
        relogin,
        relogin_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::web::WebShared;
    use std::sync::Arc;
    use std::time::Duration;

    const TOKEN: &str = "sess_0123456789abcdef0123456789abcdef";

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn entry(kind: WebSessionKind, shared: Arc<WebShared>, opened_at: Instant) -> WebSessionState {
        WebSessionState {
            resource_name: "fw01".into(),
            profile_id: "p_web".into(),
            window_label: format!("web-{TOKEN}"),
            data_dir: None,
            opened_at,
            kind,
            credential_provider: false,
            launch: None,
            shared,
            relogin: None,
            engine: None,
        }
    }

    #[test]
    fn the_chrome_prefix_and_the_remote_prefix_never_match_each_other() {
        assert!(!CHROME_LABEL_PREFIX.starts_with(WINDOW_LABEL_PREFIX));
        assert!(!WINDOW_LABEL_PREFIX.starts_with(CHROME_LABEL_PREFIX));
        assert_eq!(chrome_label(TOKEN), format!("webchrome-{TOKEN}"));
    }

    #[test]
    fn only_a_toolbar_in_its_own_session_window_is_a_caller() {
        let chrome = chrome_label(TOKEN);
        let window = format!("web-{TOKEN}");
        assert_eq!(chrome_caller(&chrome, &window), Ok(TOKEN));

        // The remote content itself, the vault UI and other windows.
        assert_eq!(chrome_caller(&window, &window), Err(NOT_A_CHROME));
        assert_eq!(chrome_caller("main", "main"), Err(NOT_A_CHROME));
        assert_eq!(chrome_caller("ssh-x", "ssh-x"), Err(NOT_A_CHROME));
        // A toolbar label hosted in another session's window, or elsewhere.
        let other = "web-sess_ffffffffffffffffffffffffffffffff";
        assert_eq!(chrome_caller(&chrome, other), Err(NOT_A_CHROME));
        assert_eq!(chrome_caller(&chrome, "main"), Err(NOT_A_CHROME));
        // Malformed tokens.
        for bad in
            ["webchrome-", "webchrome-sess_", "webchrome-sess_0123", "webchrome-sess_0123456789ABCDEF0123456789abcdef"]
        {
            let window = format!("web-{}", bad.trim_start_matches("webchrome-"));
            assert_eq!(chrome_caller(bad, &window), Err(NOT_A_CHROME), "{bad}");
        }
    }

    #[test]
    fn layout_keeps_a_fixed_toolbar_over_the_remote_content() {
        let (bar, remote) = layout(1280.0, 900.0);
        assert_eq!(bar, Bounds { x: 0.0, y: 0.0, width: 1280.0, height: CHROME_HEIGHT });
        assert_eq!(remote, Bounds { x: 0.0, y: CHROME_HEIGHT, width: 1280.0, height: 900.0 - CHROME_HEIGHT });
        // Never overlapping, never negative.
        let (bar, remote) = layout(300.0, 10.0);
        assert_eq!((bar.height, remote.y, remote.height), (10.0, 10.0, 0.0));
        let (bar, remote) = layout(-5.0, f64::NAN);
        assert_eq!((bar.width, bar.height, remote.height), (0.0, 0.0, 0.0));
    }

    #[test]
    fn the_toolbar_may_load_only_its_bundled_page() {
        let dev = url("http://localhost:1420");
        for ok in [
            "tauri://localhost/web-chrome.html",
            "http://tauri.localhost/web-chrome.html",
            "https://tauri.localhost/web-chrome.html",
        ] {
            assert!(chrome_navigation_allowed(&url(ok), None), "{ok}");
        }
        assert!(chrome_navigation_allowed(&url("http://localhost:1420/web-chrome.html"), Some(&dev)));
        for bad in [
            "http://localhost:1420/web-chrome.html", // dev origin, but no dev URL configured
            "tauri://localhost/index.html",
            "tauri://localhost/web-chrome.html/x",
            "tauri://evil/web-chrome.html",
            "http://tauri.localhost:8080/web-chrome.html",
            "https://fw01.example.com/web-chrome.html",
            "http://user@tauri.localhost/web-chrome.html",
            "about:blank",
            "data:text/html,hi",
        ] {
            assert!(!chrome_navigation_allowed(&url(bad), None), "{bad}");
        }
        assert!(!chrome_navigation_allowed(&url("http://localhost:1421/web-chrome.html"), Some(&dev)));
    }

    #[test]
    fn lock_state_follows_the_host_observed_scheme_and_pin_acceptance() {
        let never = |_: &WebOrigin| false;
        assert_eq!(lock_state(None, never), LockState::None);
        assert_eq!(lock_state(Some(&url("about:blank")), never), LockState::None);
        assert_eq!(lock_state(Some(&url("http://fw01.example.com/")), never), LockState::Insecure);
        assert_eq!(lock_state(Some(&url("https://fw01.example.com/")), never), LockState::Secure);
        let pinned = WebOrigin::of_url(&url("https://fw01.example.com")).unwrap();
        let on_pin = |o: &WebOrigin| *o == pinned;
        assert_eq!(lock_state(Some(&url("https://fw01.example.com/ng")), on_pin), LockState::Pinned);
        assert_eq!(lock_state(Some(&url("https://other.example.com/")), on_pin), LockState::Secure);
        // A pin never turns plain http into anything but insecure.
        assert_eq!(lock_state(Some(&url("http://fw01.example.com/")), |_| true), LockState::Insecure);
    }

    #[test]
    fn relogin_is_offered_for_form_sessions_only() {
        assert_eq!(relogin_availability(WebSessionKind::Form, false, false), Relogin::Available);
        assert_eq!(relogin_availability(WebSessionKind::Form, false, true), Relogin::Running);
        for kind in [WebSessionKind::HttpAuth, WebSessionKind::Open, WebSessionKind::RecipeTest] {
            for provider in [false, true] {
                assert!(matches!(relogin_availability(kind, provider, false), Relogin::Unavailable(_)), "{kind:?}");
                assert!(matches!(relogin_availability(kind, provider, true), Relogin::Unavailable(_)), "{kind:?}");
            }
        }
    }

    /// A credential-provider account is released again only after a fresh
    /// connect-time MFA check, which the toolbar cannot run: the re-run is
    /// unavailable (and says why) rather than sent to fail with
    /// `mfa_required`.
    #[test]
    fn relogin_is_unavailable_for_a_credential_provider_session() {
        for running in [false, true] {
            match relogin_availability(WebSessionKind::Form, true, running) {
                Relogin::Unavailable(reason) => assert!(reason.contains("connect again"), "{reason}"),
                other => panic!("{other:?}"),
            }
        }
        let mut e = entry(WebSessionKind::Form, WebShared::new("fw01", "https://fw01.example.com"), Instant::now());
        e.credential_provider = true;
        let state = chrome_state(&e, Instant::now());
        assert_eq!(state.relogin, "unavailable");
        assert!(state.relogin_reason.is_some_and(|r| r.contains("credential provider")));
    }

    #[test]
    fn remaining_secs_rounds_up_and_ends_at_the_deadline() {
        let now = Instant::now();
        assert_eq!(remaining_secs(now, None), None);
        assert_eq!(remaining_secs(now, Some(now)), None);
        assert_eq!(remaining_secs(now + Duration::from_secs(1), Some(now)), None);
        assert_eq!(remaining_secs(now, Some(now + Duration::from_millis(1))), Some(1));
        assert_eq!(remaining_secs(now, Some(now + Duration::from_secs(30))), Some(30));
        assert_eq!(remaining_secs(now, Some(now + Duration::from_millis(29_001))), Some(30));
    }

    #[test]
    fn the_state_is_host_observed_and_carries_no_path() {
        let opened = Instant::now();
        let shared = WebShared::new("fw01", "https://fw01.example.com");
        let s = chrome_state(&entry(WebSessionKind::Form, Arc::clone(&shared), opened), opened);
        assert_eq!(s.origin, "https://fw01.example.com");
        assert_eq!(s.lock, LockState::None, "nothing has loaded yet");
        assert_eq!((s.relogin, s.relogin_reason), ("available", None));
        assert_eq!(s.login_window_secs, None);
        assert_eq!(s.login_mode, "form");

        shared.page_load(&url("https://fw01.example.com:8443/login?token=secret#x"), true);
        let deadline = shared.start_login_window(Duration::from_secs(30));
        let s =
            chrome_state(&entry(WebSessionKind::Form, Arc::clone(&shared), opened), opened + Duration::from_secs(5));
        assert_eq!(s.origin, "https://fw01.example.com:8443");
        assert_eq!(s.lock, LockState::Secure);
        assert_eq!(s.elapsed_secs, 5);
        assert!(s.login_window_secs.is_some_and(|n| n <= 30));
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("login?") && !json.contains("secret") && !json.contains('#'), "{json}");

        shared.end_login_window(deadline);
        let running = shared.begin_relogin().expect("first re-run");
        assert!(shared.begin_relogin().is_none(), "single flight");
        let s = chrome_state(&entry(WebSessionKind::Form, Arc::clone(&shared), opened), opened);
        assert_eq!((s.relogin, s.login_window_secs), ("running", None));
        drop(running);
        assert!(!shared.relogin_running());

        let s = chrome_state(&entry(WebSessionKind::HttpAuth, shared, opened), opened);
        assert_eq!(s.relogin, "unavailable");
        assert!(s.relogin_reason.is_some());
    }
}
