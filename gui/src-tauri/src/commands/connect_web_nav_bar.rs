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
//! window's other handlers already use, never re-derived ([`nav_bar_wiring`]):
//!
//! * `allow_downloads` is the profile's, the value `build_window` hands
//!   `RemotePolicy::on_download`, and the allow-list is `RemotePolicy::origins`
//!   itself (the same `Arc`), so the bar's `web::download_decision` is the
//!   webview's decision on the same inputs (spec A6);
//! * `shared` is `RemotePolicy::shared`: the `Arc<WebShared>` whose load
//!   generation the page-load handler advances and that `TauriPage`, the fill
//!   engine's page, is cloned from. The Reload button's operator-reload mark
//!   must land on that `Arc` to reach the engine (G5);
//! * the audit identity is the session's resource name and clear `sess_…`
//!   token, as on every other `connect.web.*` line;
//! * the TLS pin gate is the window's own, cloned before it moves into the
//!   native handlers (macOS decides a download's server trust with it, and
//!   Windows refuses every bar download without one);
//! * `proxy_mode` is read from [`WebviewRoute`], failing closed.

use std::sync::Arc;

use tauri::AppHandle;

use crate::session::web::{OriginSet, WebSessionConfig, WebShared};
use crate::session::web_nav_bar::{NavBar, NavBarAudit, NavBarConfig, WebviewFrame};
use crate::session::web_tls_pin::TlsPinGate;

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
    /// Not something this build knows. Treated as proxied: the bar refuses
    /// to fetch anything itself rather than bypass a proxy it was not told
    /// about.
    Unknown,
}

impl WebviewRoute {
    /// The route of a session whose launch released its credential at
    /// `exposure`; `None` for a session without a launch (`open` mode, a
    /// recipe test), which holds no credential a proxy could substitute.
    ///
    /// Proxy mode is not wired in this tree: nothing gives a session webview
    /// a `proxy_url` (`web_proxy.rs`: "Proxy mode has no caller yet"; asserted
    /// by `no_session_webview_is_given_a_proxy_behind_the_bars_back`),
    /// `WebSessionConfig` has no proxy setting, and `check_bundle` refuses
    /// every exposure but `dom` and `handler`. The launch's exposure is the
    /// session fact proxy mode changes (T106 step 5: `launch` releasing the
    /// credential at exposure `proxy`), so the route is read from it, and an
    /// exposure this build does not know is [`Self::Unknown`].
    pub(crate) fn from_launch_exposure(exposure: Option<&str>) -> Self {
        match exposure {
            None | Some("dom") | Some("handler") => Self::Direct,
            Some("proxy") => Self::LoopbackProxy,
            Some(_) => Self::Unknown,
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

/// What the composition root holds when it attaches the bar.
pub(crate) struct NavBarInputs<'a> {
    /// The profile's validated config (`allow_downloads`).
    pub cfg: &'a WebSessionConfig,
    /// The session's resource name and token, as `RemotePolicy` logs them.
    pub resource: &'a str,
    pub token: &'a str,
    /// `RemotePolicy::origins`: the allow-list `on_download` decides on.
    pub origins: &'a Arc<OriginSet>,
    /// `RemotePolicy::shared`: the session the page-load handler feeds.
    pub shared: &'a Arc<WebShared>,
    pub network: &'a SessionNetwork,
    pub frame: WebviewFrame,
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

/// Decide the bar's configuration from the session (module docs).
pub(crate) fn nav_bar_wiring(inputs: NavBarInputs<'_>) -> NavBarWiring {
    NavBarWiring {
        allow_downloads: inputs.cfg.allow_downloads,
        origins: Arc::clone(inputs.origins),
        shared: Arc::clone(inputs.shared),
        tls_pin: inputs.network.tls_pin.clone(),
        frame: inputs.frame,
        proxy_mode: inputs.network.route.proxy_mode(),
        resource: inputs.resource.to_string(),
        token: inputs.token.to_string(),
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
    use super::*;
    use crate::session::web::{parse_web_profile, WebOrigin};
    use crate::session::web_tls_pin::{PinAudit, PinSet};
    use serde_json::json;

    const TOKEN: &str = "sess_0123456789abcdef0123456789abcdef";

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

    fn gate(pins: PinSet, origins: OriginSet) -> Arc<TlsPinGate> {
        TlsPinGate::with_operator_override(
            pins,
            origins,
            PinAudit { resource: "fw01".into(), token: TOKEN.into(), launch_id_hash: None },
            Box::new(|_| {}),
        )
    }

    /// The window's allow-list: for a launch, the server's narrowed scope,
    /// which `RemotePolicy` gets and the profile's `cfg.origins` is not.
    fn policy_origins() -> Arc<OriginSet> {
        Arc::new(OriginSet::new(vec![origin("https://fw01.example.com")]))
    }

    #[test]
    fn the_bar_takes_the_policys_inputs_and_the_engines_session() {
        for allow_downloads in [false, true] {
            let cfg = cfg(allow_downloads);
            let origins = policy_origins();
            let shared = WebShared::new("fw01", "https://fw01.example.com");
            let pin_gate = gate(PinSet::default(), (*origins).clone());
            let network = SessionNetwork { tls_pin: Some(Arc::clone(&pin_gate)), route: WebviewRoute::Direct };
            let w = nav_bar_wiring(NavBarInputs {
                cfg: &cfg,
                resource: "fw01",
                token: TOKEN,
                origins: &origins,
                shared: &shared,
                network: &network,
                frame: WebviewFrame::ShrinkToFit,
            });
            // `allow_downloads` is the profile's: what `on_download` is given.
            assert_eq!(w.allow_downloads, allow_downloads);
            assert_eq!(w.allow_downloads, cfg.allow_downloads);
            // The allow-list is `RemotePolicy::origins` itself, not a copy
            // and not the profile's wider set.
            assert!(Arc::ptr_eq(&w.origins, &origins), "same Arc<OriginSet> as RemotePolicy");
            let sso = origin("https://sso.example.com");
            assert!(cfg.origins.contains(&sso) && !w.origins.contains(&sso), "the scope, not the profile's set");
            // The operator-reload mark lands on the engine's session.
            assert!(Arc::ptr_eq(&w.shared, &shared), "same Arc<WebShared> as the fill engine");
            // The window's own pin gate, present.
            assert!(w.tls_pin.as_ref().is_some_and(|g| Arc::ptr_eq(g, &pin_gate)), "the window's pin gate");
            // The audit identity is the clear session token.
            assert_eq!((w.resource.as_str(), w.token.as_str()), ("fw01", TOKEN));
            assert!(w.token.starts_with("sess_"));
            assert!(!w.proxy_mode);
            assert_eq!(w.frame, WebviewFrame::ShrinkToFit);
        }
    }

    #[test]
    fn the_reload_mark_reaches_the_session_the_engine_polls() {
        // What the Reload button does to the wiring's `shared` is what the
        // engine (`TauriPage::take_operator_reload`) sees on its own clone.
        let cfg = cfg(false);
        let origins = policy_origins();
        let shared = WebShared::new("fw01", "https://fw01.example.com");
        let engine_view = Arc::clone(&shared);
        let network = SessionNetwork { tls_pin: None, route: WebviewRoute::Direct };
        let w = nav_bar_wiring(NavBarInputs {
            cfg: &cfg,
            resource: "fw01",
            token: TOKEN,
            origins: &origins,
            shared: &shared,
            network: &network,
            frame: WebviewFrame::HostManaged,
        });
        let url = tauri::Url::parse("https://fw01.example.com/login").unwrap();
        engine_view.page_load(&url, true);
        crate::session::web_nav_bar::mark_operator_reload(&w.shared);
        engine_view.page_load(&url, false);
        assert!(crate::session::web_nav_bar::take_operator_reload(&engine_view, engine_view.load_gen()));
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
        assert!(WebviewRoute::Unknown.proxy_mode());
        // And the wiring carries it.
        let cfg = cfg(true);
        let origins = policy_origins();
        let shared = WebShared::new("fw01", "https://fw01.example.com");
        for (route, proxied) in
            [(WebviewRoute::Direct, false), (WebviewRoute::LoopbackProxy, true), (WebviewRoute::Unknown, true)]
        {
            let network = SessionNetwork { tls_pin: None, route };
            let w = nav_bar_wiring(NavBarInputs {
                cfg: &cfg,
                resource: "fw01",
                token: TOKEN,
                origins: &origins,
                shared: &shared,
                network: &network,
                frame: WebviewFrame::ShrinkToFit,
            });
            assert_eq!(w.proxy_mode, proxied, "{route:?}");
        }
    }

    /// The route is read from the launch's exposure because no session
    /// webview is given a proxy today. The day one is (T106 step 4: Tauri's
    /// `proxy_url`, or WebView2's `--proxy-server` browser argument), this
    /// fails, so the route cannot be left saying `Direct` for a proxied
    /// webview: the Windows bar's own request would then go around the proxy.
    #[test]
    fn no_session_webview_is_given_a_proxy_behind_the_bars_back() {
        let needles = [concat!(".proxy", "_url("), concat!("proxy", "-server")];
        for (file, source) in [
            ("connect_web.rs", include_str!("connect_web.rs")),
            ("connect_web_chrome.rs", include_str!("connect_web_chrome.rs")),
        ] {
            for needle in needles {
                assert!(
                    !source.contains(needle),
                    "{file} gives the session webview a proxy ({needle}): make `WebviewRoute` report it to the nav \
                     bar (`NavBarConfig::proxy_mode`), then update this test"
                );
            }
        }
    }

    #[test]
    fn the_frame_follows_who_lays_the_remote_webview_out() {
        if cfg!(feature = "web_session_chrome") {
            assert_eq!(REMOTE_FRAME, WebviewFrame::HostManaged);
        } else {
            assert_eq!(REMOTE_FRAME, WebviewFrame::ShrinkToFit);
        }
    }
}
