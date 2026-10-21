//! Wiring the web session nav bar (`session::web_nav_bar`, back / forward /
//! reload / download) into the session window: the composition root's half
//! (docs/specs/2026-10-20-web-session-nav-controls-design.md §6–§8).
//!
//! `connect_web::build_window` attaches the bar right after it builds the
//! remote webview, in the default build and in the `web_session_chrome` one
//! (spec §7.7: the bar ships in both). The handle is kept on the session's
//! registry entry (`WebSessionState::nav_bar`) and detached at teardown:
//! `finish_session` (window destroyed, Disconnect, close) and
//! `close_web_sessions_on_exit` (app exit, before any network wait), so a
//! download in flight at quit leaves no placeholder or staging directory.
//! `detach` is idempotent in every shim; each shim also tears itself down
//! when its window closes.
//!
//! What the bar is configured from is decided here, from the values the
//! window's other handlers already use, never re-derived:
//!
//! * [`window_policy`] builds the one [`WindowPolicy`] a window has: the
//!   audit identity (resource name, clear `sess_…` token, as on every other
//!   `connect.web.*` line), the allow-list (the effective scope's, for a launch
//!   the server's narrowed set, never the profile's wider one) and the
//!   `Arc<WebShared>` the session entry, the page-load handler and the fill
//!   engine's `TauriPage` share. `RemotePolicy` embeds it, so the webview's
//!   navigation / download / page-load handlers and the bar
//!   ([`nav_bar_wiring`]) read the same allocation: the bar's
//!   `web::download_decision` is the webview's decision on the same inputs
//!   (spec A6), and the Reload button's operator-reload mark lands where the
//!   engine looks (G5);
//! * `allow_downloads` is the profile's, the value `build_window` hands
//!   `RemotePolicy::on_download`;
//! * the TLS pin gate is the window's own, cloned before it moves into the
//!   native handlers (macOS decides a download's server trust with it, and
//!   Windows refuses every bar download without one);
//! * `proxy_mode` is read from [`WebviewRoute`] ([`session_network`]), failing
//!   closed.

use std::sync::Arc;

use tauri::AppHandle;

use crate::session::web::{OriginSet, WebSessionConfig, WebShared};
use crate::session::web_nav_bar::{NavBar, NavBarAudit, NavBarConfig, WebviewFrame, BAR_HEIGHT};
use crate::session::web_recipe::EffectiveScope;
use crate::session::web_tls_pin::TlsPinGate;

// ── Routing ────────────────────────────────────────────────────────

/// The environment variable WebView2 adds to every browser process's command
/// line (Windows). `lib.rs` keeps the operator's value and appends a fixed,
/// proxy-free flag list; nothing else in this tree sets it (asserted by
/// `no_session_webview_is_given_a_proxy_behind_the_bars_back`).
#[cfg_attr(not(windows), allow(dead_code))] // only WebView2 reads it: `webview2_browser_args` on Windows
pub(crate) const WEBVIEW2_BROWSER_ARGS_ENV: &str = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS";

/// Substrings of a Chromium switch that route the webview's loads somewhere
/// the bar's own request would not go: every proxy switch (`--proxy-server`,
/// `--proxy-pac-url`, `--proxy-auto-detect`, `--proxy-bypass-list`,
/// `--no-proxy-server`, `--winhttp-proxy-resolver`, …) and the host remapping
/// ones.
const ROUTING_SWITCHES: [&str; 3] = ["proxy", "host-rules", "host-resolver-rules"];

/// How the session webview's own loads reach the network, as far as the bar
/// must know: on Windows the bar's download is a request of its own, which
/// must not go around a proxy the webview uses (`refetch_blocked`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebviewRoute {
    /// Straight to the origin (or through the computer's proxy settings,
    /// which the Windows shim reads for itself).
    Direct,
    /// Through the session's host-local proxy (proxy mode, T106).
    LoopbackProxy,
    /// WebView2's browser arguments set a proxy or remap hosts for every
    /// webview of the process.
    BrowserArgs,
    /// Not something this build can tell. Treated as proxied: the bar refuses
    /// to fetch anything itself rather than bypass a proxy it was not told
    /// about.
    Unknown,
}

impl WebviewRoute {
    /// The route of a session whose launch released its credential at
    /// `exposure`; `None` for a session without a launch (`open` mode, a
    /// recipe test), which holds no credential a proxy could substitute.
    ///
    /// Proxy mode (T106) gives a session webview a `proxy_url` only through
    /// `session/web_proxy_webview.rs`, and only for a form launch released
    /// at exposure `proxy` (`check_bundle` requires `proxy` for a recipe with
    /// a `submit_target` and refuses it for any other; asserted by
    /// `no_session_webview_is_given_a_proxy_behind_the_bars_back`). So the
    /// route is read from the launch's exposure, and an exposure this build
    /// does not know is [`Self::Unknown`].
    pub(crate) fn from_launch_exposure(exposure: Option<&str>) -> Self {
        match exposure {
            None | Some("dom") | Some("handler") => Self::Direct,
            Some("proxy") => Self::LoopbackProxy,
            Some(_) => Self::Unknown,
        }
    }

    /// The route of a session with these launches (none, or the one a form
    /// or http-auth open made): any launch that is not direct decides it.
    pub(crate) fn from_launch_exposures<'a>(exposures: impl IntoIterator<Item = &'a str>) -> Self {
        exposures.into_iter().fold(Self::Direct, |route, exposure| route.or(Self::from_launch_exposure(Some(exposure))))
    }

    /// The route WebView2's browser arguments (`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`)
    /// give every webview of the process; `None` when the variable is unset.
    ///
    /// Chromium reads its switches case-insensitively on Windows, accepts
    /// `--`, `-` and `/` prefixes, and splits the line with Windows' rules, in
    /// which `"` only groups and `\` only escapes a quote. So the value is
    /// scanned, not parsed: with every `"` and `\` dropped and ASCII lowercased,
    /// any [`ROUTING_SWITCHES`] substring anywhere is [`Self::BrowserArgs`]
    /// (`--pro""xy-server=…` included). A value that is not printable ASCII
    /// plus spaces and tabs (control characters, non-ASCII, an OS string that
    /// was not Unicode) is [`Self::Unknown`]. Both count as proxied: an
    /// unrelated switch that merely mentions `proxy` blocks the bar's download
    /// on Windows, never the other way round.
    pub(crate) fn from_browser_args(args: Option<&str>) -> Self {
        let Some(args) = args else { return Self::Direct };
        if !args.chars().all(|c| c == ' ' || c == '\t' || c.is_ascii_graphic()) {
            return Self::Unknown;
        }
        let flat: String = args.chars().filter(|c| !matches!(c, '"' | '\\')).collect::<String>().to_ascii_lowercase();
        if ROUTING_SWITCHES.iter().any(|switch| flat.contains(switch)) {
            Self::BrowserArgs
        } else {
            Self::Direct
        }
    }

    /// Both routes at once: direct only when both are.
    pub(crate) fn or(self, other: Self) -> Self {
        if self == Self::Direct {
            other
        } else {
            self
        }
    }

    /// `NavBarConfig::proxy_mode`: anything but a known direct route.
    pub(crate) fn proxy_mode(self) -> bool {
        !matches!(self, Self::Direct)
    }
}

/// How the session's webview is trusted and routed: what the bar's own
/// download must honour.
pub(crate) struct SessionNetwork {
    /// The window's TLS pin gate, the one the native handlers get.
    pub tls_pin: Option<Arc<TlsPinGate>>,
    pub route: WebviewRoute,
}

/// The session's network as the bar must see it: the window's pin gate, and
/// the route its launches' exposures and (on Windows) WebView2's browser
/// arguments imply ([`network_route`]).
pub(crate) fn session_network<'a>(
    tls_pin: Option<Arc<TlsPinGate>>,
    launch_exposures: impl IntoIterator<Item = &'a str>,
) -> SessionNetwork {
    let browser_args = webview2_browser_args();
    SessionNetwork { tls_pin, route: network_route(launch_exposures, browser_args.as_deref()) }
}

/// The pure half of [`session_network`]: the launches' route, or the browser
/// arguments' when it is not direct.
pub(crate) fn network_route<'a>(
    launch_exposures: impl IntoIterator<Item = &'a str>,
    browser_args: Option<&str>,
) -> WebviewRoute {
    WebviewRoute::from_launch_exposures(launch_exposures).or(WebviewRoute::from_browser_args(browser_args))
}

/// WebView2 reads [`WEBVIEW2_BROWSER_ARGS_ENV`] from this process when each
/// session's environment is created, so this reads the same, final value:
/// the operator's (or an administrator's) value with `lib.rs`'s fixed,
/// proxy-free suffix, which leaves every switch the operator set in place.
/// A value that is not Unicode is converted lossily, and the replacement
/// character makes it [`WebviewRoute::Unknown`].
#[cfg(windows)]
fn webview2_browser_args() -> Option<String> {
    std::env::var_os(WEBVIEW2_BROWSER_ARGS_ENV).map(|value| value.to_string_lossy().into_owned())
}

/// WKWebView and WebKitGTK do not read the variable.
#[cfg(not(windows))]
fn webview2_browser_args() -> Option<String> {
    None
}

// ── The window's policy and the bar's configuration ───────────────

/// What a session window's handlers and its nav bar are both configured
/// from, without the app handle, so the mapping is unit-tested.
/// `connect_web::RemotePolicy` embeds the one [`window_policy`] builds.
pub(crate) struct WindowPolicy {
    /// The session's resource name and token, as every `connect.web.*` line
    /// logs them.
    pub token: String,
    pub resource: String,
    /// The window's navigation allow-list: the effective scope's.
    pub origins: Arc<OriginSet>,
    /// The session the page-load handler feeds and the fill engine polls.
    pub shared: Arc<WebShared>,
}

/// The one place a window's policy is built (`build_window`): the allow-list
/// is `scope.origins` (for a launch, the server's narrowed scope, never the
/// profile's set), the session is the entry's `Arc` itself.
pub(crate) fn window_policy(
    token: &str,
    resource: &str,
    scope: &EffectiveScope,
    shared: &Arc<WebShared>,
) -> WindowPolicy {
    WindowPolicy {
        token: token.to_string(),
        resource: resource.to_string(),
        origins: Arc::new(scope.origins.clone()),
        shared: Arc::clone(shared),
    }
}

/// The bar's configuration as plain data (no `AppHandle`), so the wiring is
/// tested on every host. [`Self::into_config`] adds the app handle.
pub(crate) struct NavBarWiring {
    pub allow_downloads: bool,
    pub origins: Arc<OriginSet>,
    pub shared: Arc<WebShared>,
    pub tls_pin: Option<Arc<TlsPinGate>>,
    pub frame: WebviewFrame,
    pub proxy_mode: bool,
    pub resource: String,
    pub token: String,
}

/// Decide the bar's configuration from the window's policy, the profile and
/// the session's network (module docs).
pub(crate) fn nav_bar_wiring(
    window: &WindowPolicy,
    cfg: &WebSessionConfig,
    network: &SessionNetwork,
    frame: WebviewFrame,
) -> NavBarWiring {
    NavBarWiring {
        allow_downloads: cfg.allow_downloads,
        origins: Arc::clone(&window.origins),
        shared: Arc::clone(&window.shared),
        tls_pin: network.tls_pin.clone(),
        frame,
        proxy_mode: network.route.proxy_mode(),
        resource: window.resource.clone(),
        token: window.token.clone(),
    }
}

impl NavBarWiring {
    fn into_config(self, app: &AppHandle) -> NavBarConfig {
        NavBarConfig {
            allow_downloads: self.allow_downloads,
            origins: self.origins,
            audit: NavBarAudit { app: app.clone(), resource: self.resource, token: self.token },
            shared: self.shared,
            tls_pin: self.tls_pin,
            frame: self.frame,
            proxy_mode: self.proxy_mode,
        }
    }
}

/// How the remote webview's frame is owned in this build: the default
/// build's webview is the window's content and the shim shrinks it; the
/// toolbar window lays it out itself (`web_chrome::layout`, which leaves the
/// bar's strip free).
pub(crate) const REMOTE_FRAME: WebviewFrame =
    if cfg!(feature = "web_session_chrome") { WebviewFrame::HostManaged } else { WebviewFrame::ShrinkToFit };

/// The default build's window inner size (logical) for a profile's `window`
/// size: every shim takes the bar's strip off the bottom of the window (macOS
/// and Windows shrink the webview, GTK packs the bar below it), so the
/// window is that much taller and the page keeps the profile's size, as in
/// the toolbar window (`web_chrome::window_inner_size`).
#[cfg_attr(feature = "web_session_chrome", allow(dead_code))] // default build's window only; tested in every build
pub(crate) fn default_window_inner_size(profile_width: u32, profile_height: u32) -> (f64, f64) {
    (f64::from(profile_width), f64::from(profile_height) + BAR_HEIGHT)
}

/// Attach this platform's bar to `remote`. Call it right after the webview
/// is built: every shim queues its native work through `with_webview`, ahead
/// of the native handlers' install and of the navigation to the start URL.
pub(crate) fn attach(app: &AppHandle, remote: &tauri::Webview, wiring: NavBarWiring) -> Box<dyn NavBar> {
    let config = wiring.into_config(app);
    #[cfg(target_os = "macos")]
    {
        crate::session::web_nav_bar::macos::attach(remote, config)
    }
    #[cfg(target_os = "linux")]
    {
        crate::session::web_nav_bar::linux::attach(remote, config)
    }
    #[cfg(target_os = "windows")]
    {
        crate::session::web_nav_bar::windows::attach(remote, config)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        // No shim: the window has no bar. The bar is never a policy gate, so
        // nothing else depends on it; say so once per window.
        let _ = (remote, config);
        log::warn!("connect.web.nav_bar: this platform has no native nav bar; the window has none");
        Box::new(NoNavBar)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
struct NoNavBar;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
impl NavBar for NoNavBar {
    fn set_state(&self, _state: &crate::session::web_nav_bar::NavState) {}
    fn detach(self: Box<Self>) {}
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::session::web::{parse_web_profile, WebOrigin};
    use crate::session::web_tls_pin::{PinAudit, PinSet};
    use serde_json::json;

    const TOKEN: &str = "sess_0123456789abcdef0123456789abcdef";

    /// `lib.rs`'s own WebView2 flags, appended to the operator's value.
    const LIB_EXTRA_ARGS: &str = "--disable-features=AutofillServerCommunication,AutofillEnableAccountWalletStorage";

    /// The profile: the start URL's origin plus `sso.example.com`.
    fn cfg(allow_downloads: bool) -> WebSessionConfig {
        parse_web_profile(&json!({
            "id": "p_web",
            "name": "Console",
            "protocol": "web",
            "credential_source": { "kind": "none" },
            "web": {
                "start_url": "https://fw01.example.com/login",
                "allowed_origins": ["https://sso.example.com"],
                "login_mode": "open",
                "allow_downloads": allow_downloads,
            },
        }))
        .unwrap()
    }

    fn origin(s: &str) -> WebOrigin {
        WebOrigin::of_url(&tauri::Url::parse(s).unwrap()).unwrap()
    }

    /// A launch's effective scope, narrower than the profile: the server
    /// dropped `sso.example.com`.
    fn narrowed_scope() -> EffectiveScope {
        EffectiveScope::local(
            tauri::Url::parse("https://fw01.example.com/login").unwrap(),
            OriginSet::new(vec![origin("https://fw01.example.com")]),
            false,
        )
    }

    fn gate(origins: OriginSet) -> Arc<TlsPinGate> {
        TlsPinGate::with_operator_override(
            PinSet::default(),
            origins,
            PinAudit { resource: "fw01".into(), token: TOKEN.into(), launch_id_hash: None },
            Box::new(|_| {}),
        )
    }

    #[test]
    fn the_bar_takes_the_window_policy_built_from_the_scope_and_the_entrys_session() {
        for allow_downloads in [false, true] {
            let cfg = cfg(allow_downloads);
            let scope = narrowed_scope();
            // The registry entry's session (`session_open_web`), and a decoy
            // the mapping must not pick up.
            let entry_shared = WebShared::new("fw01", "https://fw01.example.com");
            let decoy = WebShared::new("fw01", "https://fw01.example.com");
            let window = window_policy(TOKEN, "fw01", &scope, &entry_shared);
            let pin_gate = gate(scope.origins.clone());
            let network = SessionNetwork { tls_pin: Some(Arc::clone(&pin_gate)), route: network_route(["dom"], None) };
            let w = nav_bar_wiring(&window, &cfg, &network, WebviewFrame::ShrinkToFit);

            // The session: the entry's own Arc, which the engine is cloned from.
            assert!(Arc::ptr_eq(&window.shared, &entry_shared) && Arc::ptr_eq(&w.shared, &entry_shared));
            assert!(!Arc::ptr_eq(&w.shared, &decoy), "not just any WebShared");
            // The allow-list: the scope's, not the profile's wider set, and
            // the very Arc the handlers (`RemotePolicy::window`) close over.
            let (fw01, sso) = (origin("https://fw01.example.com"), origin("https://sso.example.com"));
            assert!(cfg.origins.contains(&sso), "the profile allows sso");
            assert!(w.origins.contains(&fw01) && !w.origins.contains(&sso), "the scope does not");
            assert_eq!(w.origins.iter().count(), scope.origins.iter().count());
            assert!(Arc::ptr_eq(&w.origins, &window.origins));
            // `allow_downloads` is the profile's: what `on_download` gets.
            assert_eq!(w.allow_downloads, allow_downloads);
            // The window's own pin gate.
            assert!(w.tls_pin.as_ref().is_some_and(|g| Arc::ptr_eq(g, &pin_gate)), "the window's pin gate");
            // The audit identity is the clear session token.
            assert_eq!((w.resource.as_str(), w.token.as_str()), ("fw01", TOKEN));
            assert!(!w.proxy_mode);
            assert_eq!(w.frame, WebviewFrame::ShrinkToFit);
        }
    }

    #[test]
    fn the_reload_mark_through_the_bars_session_reaches_the_engine() {
        let cfg = cfg(false);
        let entry_shared = WebShared::new("fw01", "https://fw01.example.com");
        // What `spawn_recipe_engine` gives `TauriPage`: a clone of the entry's.
        let engine_view = Arc::clone(&entry_shared);
        let decoy = WebShared::new("fw01", "https://fw01.example.com");
        let window = window_policy(TOKEN, "fw01", &narrowed_scope(), &entry_shared);
        let w = nav_bar_wiring(&window, &cfg, &session_network(None, []), WebviewFrame::HostManaged);
        let url = tauri::Url::parse("https://fw01.example.com/login").unwrap();
        for s in [&engine_view, &decoy] {
            s.page_load(&url, true);
        }
        // The Reload button marks `NavBarConfig::shared` (`w.shared`) ...
        crate::session::web_nav_bar::mark_operator_reload(&w.shared);
        for s in [&engine_view, &decoy] {
            s.page_load(&url, false);
        }
        // ... and the engine, polling its own clone, sees the mark; a session
        // the bar was not given does not.
        assert!(crate::session::web_nav_bar::take_operator_reload(&engine_view, engine_view.load_gen()));
        assert!(!crate::session::web_nav_bar::take_operator_reload(&decoy, decoy.load_gen()));
        assert_eq!(w.frame, WebviewFrame::HostManaged);
    }

    #[test]
    fn proxy_mode_follows_the_launch_exposure_and_fails_closed() {
        // No launch (open mode, recipe test) and the two exposures this
        // build accepts are direct.
        for exposure in [None, Some("dom"), Some("handler")] {
            let route = WebviewRoute::from_launch_exposure(exposure);
            assert_eq!(route, WebviewRoute::Direct, "{exposure:?}");
            assert!(!route.proxy_mode(), "{exposure:?}");
        }
        // Proxy mode's exposure is proxied.
        let route = WebviewRoute::from_launch_exposure(Some("proxy"));
        assert_eq!(route, WebviewRoute::LoopbackProxy);
        assert!(route.proxy_mode());
        // Anything else is unknown, and unknown is proxied (refetch blocked).
        for exposure in ["", "Proxy", "dom ", "header", "socks"] {
            let route = WebviewRoute::from_launch_exposure(Some(exposure));
            assert_eq!(route, WebviewRoute::Unknown, "{exposure:?}");
            assert!(route.proxy_mode(), "{exposure:?}");
        }
        assert!(WebviewRoute::Unknown.proxy_mode() && WebviewRoute::BrowserArgs.proxy_mode());
        // Over a session's launches: any non-direct one decides.
        assert_eq!(WebviewRoute::from_launch_exposures([]), WebviewRoute::Direct);
        assert_eq!(WebviewRoute::from_launch_exposures(["dom"]), WebviewRoute::Direct);
        assert_eq!(WebviewRoute::from_launch_exposures(["handler", "dom"]), WebviewRoute::Direct);
        assert_eq!(WebviewRoute::from_launch_exposures(["dom", "proxy"]), WebviewRoute::LoopbackProxy);
        assert_eq!(WebviewRoute::from_launch_exposures(["odd", "dom"]), WebviewRoute::Unknown);
        // And the wiring carries it.
        let cfg = cfg(true);
        let window = window_policy(TOKEN, "fw01", &narrowed_scope(), &WebShared::new("fw01", "https://fw01"));
        for (exposures, proxied) in [(vec![], false), (vec!["dom"], false), (vec!["proxy"], true), (vec!["x"], true)] {
            let network = SessionNetwork { tls_pin: None, route: network_route(exposures.clone(), None) };
            let w = nav_bar_wiring(&window, &cfg, &network, WebviewFrame::ShrinkToFit);
            assert_eq!(w.proxy_mode, proxied, "{exposures:?}");
        }
    }

    #[test]
    fn webview2_browser_args_that_route_the_webview_count_as_proxied() {
        use WebviewRoute::{BrowserArgs, Direct, Unknown};
        // Unset, empty and unrelated switches are direct, and so is what
        // lib.rs appends itself.
        for args in [None, Some(""), Some("   "), Some("--disable-gpu --lang=pt-BR"), Some(LIB_EXTRA_ARGS)] {
            assert_eq!(WebviewRoute::from_browser_args(args), Direct, "{args:?}");
        }
        // Every proxy switch, the no-proxy one (it changes routing too) and
        // host remapping.
        for args in [
            "--proxy-server=http://egress.corp:3128",
            "--proxy-pac-url=http://wpad.corp/proxy.pac",
            "--proxy-auto-detect",
            "--no-proxy-server",
            "--proxy-bypass-list=*.corp",
            "--winhttp-proxy-resolver",
            "--host-resolver-rules=\"MAP * 10.0.0.1\"",
            "--host-rules=\"MAP fw01.example.com 10.0.0.1\"",
        ] {
            assert_eq!(WebviewRoute::from_browser_args(Some(args)), BrowserArgs, "{args}");
        }
        // Mixed into a longer line, any casing, quoted, split by quotes,
        // escaped, or with the other switch prefixes Chromium accepts on
        // Windows; and after lib.rs appended its own flags.
        let operator = "--disable-gpu --PROXY-Server=\"http://p:3128\" --lang=en";
        let appended = format!("{operator} {LIB_EXTRA_ARGS}");
        for args in [
            operator,
            "\"--proxy-server=http://p:3128\"",
            "--pro\"\"xy-server=http://p:3128",
            "--pro\\\"xy-server=p",
            "-proxy-server=p",
            "/proxy-server=p",
            "--No-Proxy-Server",
            appended.as_str(),
        ] {
            assert_eq!(WebviewRoute::from_browser_args(Some(args)), BrowserArgs, "{args}");
        }
        // A value this cannot read is unknown: control characters, non-ASCII,
        // the replacement character a non-Unicode OS string becomes.
        for args in ["--lang=en\n--proxy-server=p", "--a\u{0}", "--lang=pt\u{e9}", "--x=\u{fffd}"] {
            assert_eq!(WebviewRoute::from_browser_args(Some(args)), Unknown, "{args:?}");
        }
        for args in ["--proxy-server=p", "--x=\u{fffd}"] {
            assert!(WebviewRoute::from_browser_args(Some(args)).proxy_mode(), "{args:?}");
        }
        // Folded with the launch: either one proxied makes the session proxied.
        assert_eq!(network_route(["dom"], Some("--disable-gpu")), Direct);
        assert_eq!(network_route(["dom"], Some("--proxy-server=p")), BrowserArgs);
        assert_eq!(network_route(["proxy"], None), WebviewRoute::LoopbackProxy);
        assert_eq!(network_route([], Some("--x=\u{fffd}")), Unknown);
        // The literal above is lib.rs's, so its own flags never block the bar.
        assert!(include_str!("../lib.rs").contains(LIB_EXTRA_ARGS), "keep LIB_EXTRA_ARGS in step with lib.rs");
        // Outside Windows no webview reads the variable.
        if !cfg!(windows) {
            assert_eq!(webview2_browser_args(), None);
        }
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The route is read from the launch's exposure and WebView2's browser
    /// arguments because nothing else gives a session webview a proxy. Proxy
    /// mode (T106) does, and only through `session/web_proxy_webview.rs`,
    /// for a session whose launch was released at exposure `proxy` — which
    /// is exactly what `WebviewRoute::from_launch_exposure` reads as
    /// `LoopbackProxy`. The day anything else does (Tauri's `proxy_url`
    /// elsewhere, a browser argument, a host remap, wry's
    /// `additional_browser_args`, or another writer of the WebView2
    /// variable), this fails, so the route cannot be left saying `Direct`
    /// for a proxied webview: the Windows bar's own request would then go
    /// around the proxy. Scans `lib.rs` and every source file under
    /// `commands/` and `session/` except this file; the proxy modules are
    /// scanned too, with `proxy_url(` allowed only where the proxy defines
    /// its URL (`web_proxy_listener.rs`) and where the webview is pointed at
    /// it (`web_proxy_webview.rs`). No file may set `additional_browser_args`
    /// (wry drops `--proxy-server` silently when it is set).
    #[test]
    fn no_session_webview_is_given_a_proxy_behind_the_bars_back() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![src.join("lib.rs")];
        rust_files(&src.join("commands"), &mut files);
        rust_files(&src.join("session"), &mut files);
        let needles = [
            concat!("proxy", "_url("),
            concat!("--", "proxy"),
            concat!("proxy", "-server"),
            concat!("proxy", "-pac-url"),
            concat!("proxy", "-auto-detect"),
            concat!("host", "-rules"),
            concat!("host", "-resolver-rules"),
            concat!("additional", "_browser_args("),
        ];
        let env_var = concat!("WEBVIEW2_", "ADDITIONAL_BROWSER_ARGUMENTS");
        let mut scanned = Vec::new();
        let proxy_url_allowed = ["web_proxy_listener.rs", "web_proxy_webview.rs"];
        for path in &files {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if name == "connect_web_nav_bar.rs" {
                continue;
            }
            // Lossy, so a stray non-UTF-8 byte neither panics nor hides an
            // ASCII needle next to it.
            let source = String::from_utf8_lossy(&std::fs::read(path).unwrap()).into_owned();
            for needle in needles {
                if needle == concat!("proxy", "_url(") && proxy_url_allowed.contains(&name) {
                    continue;
                }
                assert!(
                    !source.contains(needle),
                    "{} gives a webview a proxy or a route ({needle}): make `WebviewRoute` report it to the nav bar \
                     (`NavBarConfig::proxy_mode`), then update this test",
                    path.display()
                );
            }
            // Only lib.rs writes the WebView2 variable, with fixed flags this
            // module knows; any other writer must go through
            // `WebviewRoute::from_browser_args` first.
            assert!(
                name == "lib.rs" || !source.contains(env_var),
                "{} touches {env_var}: route it through `WebviewRoute::from_browser_args`, then update this test",
                path.display()
            );
            scanned.push(name.to_string());
        }
        for expected in [
            "lib.rs",
            "connect_web.rs",
            "connect_web_chrome.rs",
            "web.rs",
            "windows.rs",
            "linux.rs",
            "web_proxy_listener.rs",
            "web_proxy_webview.rs",
        ] {
            assert!(scanned.iter().any(|n| n == expected), "{expected} was not scanned");
        }
        assert!(scanned.len() > 50, "only {} files scanned", scanned.len());
    }

    #[test]
    fn the_frame_follows_who_lays_the_remote_webview_out() {
        if cfg!(feature = "web_session_chrome") {
            assert_eq!(REMOTE_FRAME, WebviewFrame::HostManaged);
        } else {
            assert_eq!(REMOTE_FRAME, WebviewFrame::ShrinkToFit);
        }
    }

    #[test]
    fn both_builds_keep_the_page_at_the_profiles_size() {
        use crate::session::web_chrome::{self, CHROME_HEIGHT};
        for (w, h) in [(1280, 860), (400, 400), (10_000, 10_000)] {
            // Default build: the window is the page plus the bar's strip,
            // which every shim takes off the bottom.
            let (width, height) = default_window_inner_size(w, h);
            assert_eq!((width, height - BAR_HEIGHT), (f64::from(w), f64::from(h)), "{w}x{h}");
            // The toolbar window: the same page, plus the toolbar on top.
            let (cw, ch) = web_chrome::window_inner_size(w, h);
            assert_eq!((cw, ch), (width, height + CHROME_HEIGHT), "{w}x{h}");
            assert_eq!(web_chrome::layout(cw, ch).remote.height, f64::from(h));
        }
    }
}
