//! Web Application Connect, proxy mode — the webview side
//! (features/web-application-connect.md §10; T106 step 4).
//!
//! The one place a session webview is given a proxy. Everything the window
//! needs from [`super::web_proxy_listener::WebProxy`] goes through here:
//!
//! * **Whether proxy mode can run at all** ([`proxy_support`]). Only where a
//!   session has been run end to end and only in a build that compiled the
//!   platform hook:
//!   - **macOS 14 or later, in a build with the `web_proxy_mode` feature**
//!     (`tauri/macos-proxy`, i.e. wry's `mac-proxy`). wry sets the
//!     window's `WKWebsiteDataStore.proxyConfigurations` with an HTTP
//!     `CONNECT` `nw_proxy_config`, both macOS 14 APIs, with no run-time
//!     version check — so below macOS 14 the host refuses before anything
//!     is launched. Without the feature wry drops `proxy_url` on macOS
//!     *silently*, so the host refuses then too rather than open a window
//!     that would talk to the server directly.
//!   - **Windows and Linux: unavailable.** WebView2 gets the proxy as
//!     Chromium's proxy switch in the window's own environment, which wry
//!     adds only when no `additional_browser_args` is set — this crate sets
//!     none (asserted by
//!     `connect_web_nav_bar::no_session_webview_is_given_a_proxy_behind_the_bars_back`);
//!     nothing of it has been run. WebKitGTK gets `NetworkProxySettings` on
//!     the window's own ephemeral `WebContext`, and since it raises
//!     `load-failed-with-tls-errors` for main-resource loads only, each
//!     session leaf is allowed for its host on that context before the first
//!     load ([`pre_register_leaves`], wired in `connect_web`). That path —
//!     WebKitGTK's `CONNECT` through the proxy, the pre-registered leaf, the
//!     substitution and the scrub — is exercised under Xvfb by
//!     `webkitgtk_tests` (a WebKitGTK view built the way wry builds an
//!     incognito one, not a Tauri window). Proxy mode still ships on each
//!     platform only once a run of the real session window there confirms
//!     it.
//!
//!   Proxy mode never falls back to a DOM fill: an unavailable platform
//!   refuses the open, before the MFA ticket or any credential is spent.
//! * **The route** ([`route_window`] / [`route_webview`]): `proxy_url`
//!   pointed at the session's loopback listener.
//! * **The trust** ([`webview_pins`]): the two pins the Phase 4 gate is given
//!   for the window instead of the profile's — the session CA's (issuer path,
//!   host-bound; the chain WebKit evaluates is `[leaf, session CA]`) and the
//!   session leaf key's (leaf path). The profile's own `tls_pin_sha256` moves
//!   to the proxy's upstream leg, where the real server is verified.

use tauri::Url;

use super::web_proxy_listener::WebProxy;
use super::web_tls_pin::PinSet;

/// Whether a proxy-mode session can be opened here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySupport {
    Available,
    /// Fixed operator-facing text naming why not.
    Unavailable(&'static str),
}

impl ProxySupport {
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::Available => None,
            Self::Unavailable(reason) => Some(reason),
        }
    }
}

/// The host this build runs on, as far as proxy mode cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    /// macOS with its major version (`NSProcessInfo.operatingSystemVersion`).
    /// Built only from `NSProcessInfo` on macOS; elsewhere only the tests,
    /// which decide every platform on every host, construct it.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    MacOs {
        major: i64,
    },
    Windows,
    Linux,
    Other,
}

/// Whether this build compiled wry's macOS proxy hook (`tauri/macos-proxy`,
/// through the GUI's `web_proxy_mode` feature).
pub const MACOS_PROXY_BUILT: bool = cfg!(feature = "web_proxy_mode");

/// The first macOS release with the `nw_proxy_config` API wry's hook calls.
pub const MACOS_PROXY_MIN_MAJOR: i64 = 14;

/// The decision, without the host: unit-tested for every platform.
pub fn support_for(platform: HostPlatform, macos_proxy_built: bool) -> ProxySupport {
    match platform {
        HostPlatform::MacOs { major } if major < MACOS_PROXY_MIN_MAJOR => ProxySupport::Unavailable(
            "proxy mode needs macOS 14 or later (the webview proxy API it uses does not exist before); this \
             profile signs in only through the session proxy, so it is not opened",
        ),
        HostPlatform::MacOs { .. } if !macos_proxy_built => ProxySupport::Unavailable(
            "this build of BastionVault was made without proxy mode (the `web_proxy_mode` build feature); this \
             profile signs in only through the session proxy, so it is not opened",
        ),
        HostPlatform::MacOs { .. } => ProxySupport::Available,
        HostPlatform::Windows => ProxySupport::Unavailable(
            "proxy mode is not available on Windows yet: it has not been run against WebView2; this profile signs \
             in only through the session proxy, so it is not opened",
        ),
        HostPlatform::Linux => ProxySupport::Unavailable(
            "proxy mode is not available on Linux yet: it has not been run against WebKitGTK; this profile signs \
             in only through the session proxy, so it is not opened",
        ),
        HostPlatform::Other => ProxySupport::Unavailable("proxy mode is not available on this platform"),
    }
}

/// [`support_for`] on this host.
pub fn proxy_support() -> ProxySupport {
    support_for(host_platform(), MACOS_PROXY_BUILT)
}

fn host_platform() -> HostPlatform {
    if cfg!(target_os = "macos") {
        macos_platform()
    } else if cfg!(windows) {
        HostPlatform::Windows
    } else if cfg!(target_os = "linux") {
        HostPlatform::Linux
    } else {
        HostPlatform::Other
    }
}

#[cfg(target_os = "macos")]
fn macos_platform() -> HostPlatform {
    // Thread-safe, no main-thread requirement.
    let version = objc2_foundation::NSProcessInfo::processInfo().operatingSystemVersion();
    HostPlatform::MacOs { major: i64::try_from(version.majorVersion).unwrap_or(0) }
}

#[cfg(not(target_os = "macos"))]
fn macos_platform() -> HostPlatform {
    HostPlatform::Other
}

/// The URL the session webview's `proxy_url` is set to.
fn listener_url(proxy: &WebProxy) -> Result<Url, String> {
    Url::parse(&proxy.proxy_url()).map_err(|e| format!("the session proxy's address is not a URL: {e}"))
}

/// Point a session window (the default build's single webview) at the
/// session proxy. `None` leaves the builder as it was.
#[cfg(not(feature = "web_session_chrome"))]
pub fn route_window<'a, R: tauri::Runtime, M: tauri::Manager<R>>(
    builder: tauri::WebviewWindowBuilder<'a, R, M>,
    proxy: Option<&WebProxy>,
) -> Result<tauri::WebviewWindowBuilder<'a, R, M>, String> {
    match proxy {
        None => Ok(builder),
        Some(proxy) => Ok(builder.proxy_url(listener_url(proxy)?)),
    }
}

/// The same for the remote webview of a toolbar window (`web_session_chrome`).
#[cfg(feature = "web_session_chrome")]
pub fn route_webview<R: tauri::Runtime>(
    builder: tauri::WebviewBuilder<R>,
    proxy: Option<&WebProxy>,
) -> Result<tauri::WebviewBuilder<R>, String> {
    match proxy {
        None => Ok(builder),
        Some(proxy) => Ok(builder.proxy_url(listener_url(proxy)?)),
    }
}

/// WebKitGTK: allow each session leaf for its host on the window's own
/// (ephemeral, per-session) `WebContext`, before the first load.
/// `load-failed-with-tls-errors` — what the Phase 4 shim answers — is raised
/// for main-resource loads only, so without this a sub-resource from another
/// session origin would fail; the shim stays as the fallback for a main
/// load. The exception names the exact leaf (WebKitGTK compares the presented
/// certificate with it), for that host, in that context only; nothing is
/// written to any trust store. Returns how many leaves were registered.
#[cfg(target_os = "linux")]
pub fn pre_register_leaves(view: &webkit2gtk::WebView, leaves: &[(String, Vec<u8>)]) -> Result<usize, String> {
    use webkit2gtk::{WebContextExt, WebViewExt};

    let context = view.context().ok_or_else(|| "the session webview has no WebContext".to_string())?;
    for (host, der) in leaves {
        let pem = pem::encode(&pem::Pem::new("CERTIFICATE", der.clone()));
        let certificate = webkit2gtk::gio::TlsCertificate::from_pem(&pem)
            .map_err(|e| format!("the session leaf for {host} could not be loaded: {e}"))?;
        context.allow_tls_certificate_for_host(&certificate, super::web_proxy::bare_host(host));
    }
    Ok(leaves.len())
}

/// The pins the window's Phase 4 gate gets in proxy mode: the session CA's
/// and the session leaf key's, nothing else. Every origin the window may
/// load is terminated by the proxy (an `allow_insecure_http` profile is
/// refused for proxy mode), so the certificate the webview sees for any of
/// them is a session leaf.
pub fn webview_pins(proxy: &WebProxy) -> Result<PinSet, String> {
    PinSet::from_strs(&[proxy.ca_pin().to_string(), proxy.leaf_pin().to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_mode_runs_only_on_macos_14_with_the_hook_built() {
        assert_eq!(support_for(HostPlatform::MacOs { major: 14 }, true), ProxySupport::Available);
        assert_eq!(support_for(HostPlatform::MacOs { major: 27 }, true), ProxySupport::Available);
        for major in [10, 11, 12, 13] {
            let s = support_for(HostPlatform::MacOs { major }, true);
            assert!(s.reason().is_some_and(|r| r.contains("macOS 14")), "{major}: {s:?}");
        }
        let s = support_for(HostPlatform::MacOs { major: 15 }, false);
        assert!(s.reason().is_some_and(|r| r.contains("web_proxy_mode")), "{s:?}");
        // Never enabled where no run has confirmed it, whatever the build.
        for (platform, name) in [(HostPlatform::Windows, "Windows"), (HostPlatform::Linux, "Linux")] {
            for built in [false, true] {
                let s = support_for(platform, built);
                assert!(s.reason().is_some_and(|r| r.contains(name)), "{platform:?}: {s:?}");
            }
        }
        assert!(support_for(HostPlatform::Other, true).reason().is_some());
    }

    #[test]
    fn this_host_answers_without_panicking() {
        let s = proxy_support();
        if !cfg!(target_os = "macos") || !MACOS_PROXY_BUILT {
            assert!(s.reason().is_some(), "{s:?}");
        }
    }
}

/// The Linux half of T106 step 4, run against a real WebKitGTK under Xvfb
/// (the spike only read it). A WebKitGTK view is built the way wry builds an
/// incognito one — an ephemeral `WebContext` whose data manager gets custom
/// `NetworkProxySettings` pointing at the session proxy — and loads a login
/// page from a local https "application" through the proxy:
///
/// * **without** the leaves pre-registered, WebKitGTK refuses the session
///   leaf (`load-failed-with-tls-errors`) and the sign-in never reaches the
///   application — the trust really is the per-host exception, nothing else;
/// * **with** them ([`pre_register_leaves`]), the page loads through the
///   proxy (which records the termination), an image from a *second* session
///   origin loads through it too (a sub-resource, for which WebKitGTK raises
///   no TLS-error signal — only the pre-registered leaf can let it through),
///   the form posts the placeholder, the application receives the real
///   secret, and the page's title — the application's echo of the request —
///   carries the placeholder, never the secret.
///
/// Ignored by default: it needs a display (`xvfb-run`) and
/// `app.bv-proxy.test` / `assets.bv-proxy.test` resolving to 127.0.0.1 for
/// the proxy's upstream dial (`docker run --add-host app.bv-proxy.test:127.0.0.1
/// --add-host assets.bv-proxy.test:127.0.0.1`); WebKitGTK itself never
/// resolves them, so a load that bypassed the proxy could not succeed.
/// Run with `cargo test -p bastion-vault-gui --lib webkitgtk -- --ignored
/// --test-threads=1`.
#[cfg(all(test, target_os = "linux"))]
mod webkitgtk_tests {
    use std::cell::{Cell, RefCell};
    use std::convert::Infallible;
    use std::net::Ipv4Addr;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use bastion_vault::utils::tls_pin::SpkiPin;
    use gtk::prelude::*;
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use webkit2gtk::{
        NetworkProxyMode, NetworkProxySettings, WebContext, WebContextExt, WebView, WebViewExt, WebsiteDataManagerExt,
    };

    use super::*;
    use crate::session::web_proxy::{BodyType, SessionSecret, SubmitTarget, TerminationScope};
    use crate::session::web_proxy_listener::{ProxyConfig, ProxyEvents, ProxyInjection};

    const HOST: &str = "app.bv-proxy.test";
    /// A second session origin, for a sub-resource: WebKitGTK raises no
    /// `load-failed-with-tls-errors` for one, so only the pre-registered leaf
    /// can let it load.
    const ASSET_HOST: &str = "assets.bv-proxy.test";
    const SECRET: &str = "s3cret pw&\"<x>";
    /// A 1x1 GIF, so the page's `<img>` fires `onload`.
    const PIXEL: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";

    type Handler = Arc<dyn Fn(&str, Bytes) -> (&'static str, Vec<u8>) + Send + Sync>;

    /// A local https server for `host` (self-signed), answering every
    /// request with `handler(path, body)`. Returns its port and certificate.
    async fn start_server(host: &str, handler: Handler) -> (u16, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![host.to_string()]).unwrap().self_signed(&key).unwrap();
        let cert_der = cert.der().to_vec();
        let config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(cert_der.clone())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(sock).await else { return };
                    let service = service_fn(move |req: Request<Incoming>| {
                        let handler = Arc::clone(&handler);
                        async move {
                            let path = req.uri().path().to_string();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let (content_type, page) = handler(&path, body);
                            let res = Response::builder()
                                .header("content-type", content_type)
                                .body(Full::new(Bytes::from(page)))
                                .unwrap();
                            Ok::<_, Infallible>(res)
                        }
                    });
                    let _ =
                        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), service).await;
                });
            }
        });
        (port, cert_der)
    }

    struct Run {
        /// The echo's title, once the sign-in's response loaded.
        title: Option<String>,
        final_title: Option<String>,
        tls_errors: u32,
        terminated: bool,
        asset_terminated: bool,
        asset_hits: Vec<String>,
        received: Vec<String>,
        placeholder: String,
        /// What happened, for a failure message: load events (`event uri-path`),
        /// load failures and the proxy's own events. Origins, paths of this
        /// test's own pages and fixed names only.
        trace: Vec<String>,
    }

    /// One session: proxy, WebKitGTK view, load, then pump the GTK loop
    /// until the sign-in's echo arrives, a TLS error is raised, or 30 s pass.
    /// Which session leaves are allowed on the context before the load.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum PreRegister {
        None,
        /// The application's host only, not the second origin's.
        MainOnly,
        All,
    }

    fn run_session(runtime: &tokio::runtime::Runtime, pre_register: PreRegister) -> Run {
        let secret = SessionSecret::new(SECRET.to_string()).unwrap();
        let placeholder = secret.placeholder().to_string();

        // The second session origin: serves the login page's image.
        let asset_hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let hits = Arc::clone(&asset_hits);
        let (asset_port, asset_cert) = runtime.block_on(start_server(
            ASSET_HOST,
            Arc::new(move |path, _| {
                hits.lock().unwrap().push(path.to_string());
                ("image/gif", PIXEL.to_vec())
            }),
        ));
        let asset_origin = format!("https://{ASSET_HOST}:{asset_port}");

        // The application: `GET /` is a login form holding the placeholder
        // (standing in for the recipe's fill) that submits itself once the
        // image from the second origin has loaded; `POST /login` records the
        // body and echoes it in the page title.
        let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let login_page = format!(
            "<html><head><title>login</title></head><body>\
             <form method=\"post\" action=\"/login\">\
             <input type=\"password\" name=\"password\" value=\"{placeholder}\"></form>\
             <img src=\"{asset_origin}/pixel.gif\" onload=\"document.forms[0].submit()\" \
             onerror=\"document.title='asset refused'\"></body></html>"
        );
        let (port, cert_der) = runtime.block_on(start_server(
            HOST,
            Arc::new(move |path, body| {
                if path == "/login" {
                    let body = String::from_utf8_lossy(&body).into_owned();
                    sink.lock().unwrap().push(body.clone());
                    let page = format!("<html><head><title>received {body}</title></head><body>ok</body></html>");
                    ("text/html; charset=utf-8", page.into_bytes())
                } else {
                    ("text/html; charset=utf-8", login_page.clone().into_bytes())
                }
            }),
        ));
        let origin = format!("https://{HOST}:{port}");
        let proxy_trace: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let proxy_sink = Arc::clone(&proxy_trace);
        let proxy = runtime
            .block_on(async {
                WebProxy::start(ProxyConfig {
                    scope: TerminationScope::new([origin.as_str(), asset_origin.as_str()]).unwrap(),
                    // The servers' self-signed certificates, pinned as a
                    // profile would pin an appliance's: the upstream leg.
                    pins: PinSet::from_strs(&[
                        SpkiPin::of_certificate(&cert_der).unwrap().to_string(),
                        SpkiPin::of_certificate(&asset_cert).unwrap().to_string(),
                    ])
                    .unwrap(),
                    events: ProxyEvents::new(move |e| proxy_sink.lock().unwrap().push(format!("{e:?}"))),
                })
                .await
            })
            .unwrap();
        proxy
            .arm(ProxyInjection { secret, target: SubmitTarget::new(&origin, "/login", BodyType::Form).unwrap() })
            .unwrap();

        // As wry builds an incognito webview given a proxy.
        let context = WebContext::new_ephemeral();
        let manager = context.website_data_manager().expect("an ephemeral context has a data manager");
        let mut settings = NetworkProxySettings::new(Some(&proxy.proxy_url()), &[]);
        manager.set_network_proxy_settings(NetworkProxyMode::Custom, Some(&mut settings));
        let view = WebView::with_context(&context);
        let window = gtk::Window::new(gtk::WindowType::Toplevel);
        window.add(&view);
        window.show_all();
        let leaves: Vec<(String, Vec<u8>)> = match pre_register {
            PreRegister::None => Vec::new(),
            PreRegister::MainOnly => proxy.session_leaves().iter().filter(|(h, _)| h == HOST).cloned().collect(),
            PreRegister::All => proxy.session_leaves().to_vec(),
        };
        assert_eq!(pre_register_leaves(&view, &leaves).unwrap(), leaves.len());

        let tls_errors = Rc::new(Cell::new(0u32));
        let counter = Rc::clone(&tls_errors);
        view.connect_load_failed_with_tls_errors(move |_, _, _, _| {
            counter.set(counter.get() + 1);
            false
        });
        let trace = Rc::new(RefCell::new(Vec::<String>::new()));
        let log = Rc::clone(&trace);
        view.connect_load_changed(move |v, event| {
            let path = v.uri().and_then(|u| tauri::Url::parse(&u).ok()).map(|u| u.path().to_string());
            log.borrow_mut().push(format!("load {event:?} {}", path.unwrap_or_default()));
        });
        let log = Rc::clone(&trace);
        view.connect_load_failed(move |_, event, _, error| {
            log.borrow_mut().push(format!("load_failed {event:?} {error}"));
            false
        });
        view.load_uri(&format!("{origin}/"));

        // The echo's title, polled: it is set while the response is parsed.
        let echo = |v: &WebView| v.title().filter(|t| t.starts_with("received")).map(|t| t.to_string());
        let main = gtk::glib::MainContext::default();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut title = None;
        let refused_asset = |v: &WebView| v.title().is_some_and(|t| t == "asset refused");
        while Instant::now() < deadline && title.is_none() && tls_errors.get() == 0 && !refused_asset(&view) {
            while main.iteration(false) {}
            title = echo(&view);
            std::thread::sleep(Duration::from_millis(10));
        }
        // A little longer after a refusal, so a load that was going to get
        // past it would have.
        if tls_errors.get() > 0 {
            let settle = Instant::now() + Duration::from_secs(2);
            while Instant::now() < settle {
                while main.iteration(false) {}
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let mut trace = trace.borrow().clone();
        trace.extend(proxy_trace.lock().unwrap().iter().cloned());
        let final_title = view.title().map(|t| t.to_string());
        trace.push(format!("final title {final_title:?}"));
        let run = Run {
            title,
            final_title,
            tls_errors: tls_errors.get(),
            terminated: proxy.has_terminated(HOST, port),
            asset_terminated: proxy.has_terminated(ASSET_HOST, asset_port),
            asset_hits: asset_hits.lock().unwrap().clone(),
            received: received.lock().unwrap().clone(),
            placeholder,
            trace,
        };
        window.close();
        proxy.shutdown();
        run
    }

    #[test]
    #[ignore = "needs Xvfb and the *.bv-proxy.test hosts -> 127.0.0.1; run in the Linux container (see the module docs)"]
    fn webkitgtk_signs_in_through_the_session_proxy_only_with_every_leaf_pre_registered() {
        gtk::init().expect("GTK needs a display: run under xvfb-run");
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();

        // Negative control: the proxy is used, its leaf is not trusted, and
        // nothing reaches the application's sign-in.
        let refused = run_session(&runtime, PreRegister::None);
        assert!(refused.tls_errors >= 1, "WebKitGTK accepted a session leaf nobody registered: {:#?}", refused.trace);
        assert!(refused.terminated, "WebKitGTK did not send its CONNECT to the session proxy");
        assert!(refused.received.is_empty(), "the sign-in reached the application: {:?}", refused.received.len());
        assert_eq!(refused.title, None);
        assert!(refused.asset_hits.is_empty());

        // The main page's leaf only: the page loads, but the image from the
        // second session origin is refused without any TLS-error signal —
        // WebKitGTK raises none for a sub-resource — so the page never signs
        // in. This is why every leaf is pre-registered, not left to the
        // Phase 4 handler.
        let partial = run_session(&runtime, PreRegister::MainOnly);
        assert_eq!(partial.tls_errors, 0, "a sub-resource raised the TLS-error signal: {:#?}", partial.trace);
        assert!(partial.asset_terminated, "the second origin did not go through the session proxy");
        assert!(partial.asset_hits.is_empty(), "the sub-resource loaded without its leaf: {:#?}", partial.trace);
        assert_eq!(partial.final_title.as_deref(), Some("asset refused"), "{:#?}", partial.trace);
        assert!(partial.received.is_empty());

        // With every leaf pre-registered: the whole sign-in, through the
        // proxy, with the secret on the wire only.
        let ok = run_session(&runtime, PreRegister::All);
        assert_eq!(ok.tls_errors, 0, "WebKitGTK refused the pre-registered session leaf: {:#?}", ok.trace);
        assert!(ok.terminated, "the page did not load through the session proxy");
        // The sub-resource from the second session origin loaded through the
        // proxy on its pre-registered leaf (no TLS-error signal exists for
        // it, so nothing else could have let it through).
        assert!(ok.asset_terminated, "the second origin did not go through the session proxy: {:#?}", ok.trace);
        assert_eq!(ok.asset_hits, vec!["/pixel.gif".to_string()], "the sub-resource did not load: {:#?}", ok.trace);
        let form_secret = urlencoding::encode(SECRET).replace("%20", "+");
        assert_eq!(ok.received, vec![format!("password={form_secret}")], "the application did not get the secret");
        let title = ok.title.unwrap_or_else(|| panic!("the sign-in's echo never loaded: {:#?}", ok.trace));
        assert!(title.contains(&ok.placeholder), "the echo was not scrubbed back to the placeholder: {title:?}");
        assert!(!title.contains(&form_secret) && !title.contains(SECRET), "the secret reached the page");
    }
}
