//! macOS shim for the web session nav bar: a native AppKit strip with back,
//! forward, reload and download at the bottom of the session window
//! (docs/specs/2026-10-20-web-session-nav-controls-design.md §6, §7, §8).
//!
//! **Layout.** The bar is an `NSVisualEffectView` added as a sibling of the
//! WKWebView inside the webview's superview — the window's content view —
//! and pinned to its bottom edge by autoresizing. The window's content view
//! is never replaced and nothing of wry's is removed. With
//! [`WebviewFrame::ShrinkToFit`] (the default build, where wry sizes the
//! webview to its superview with flexible width and height) the webview's
//! frame is reduced once by [`BAR_HEIGHT`](super::BAR_HEIGHT); autoresizing
//! keeps that bottom margin on every resize, so no resize observer is
//! needed and nothing fights wry. With [`WebviewFrame::HostManaged`] (the
//! `web_session_chrome` window, whose resize handler sets the remote's
//! bounds itself) the shim only places the bar. The buttons refuse first
//! responder, so a click on the bar leaves keyboard focus in the page.
//!
//! **State.** Back, forward and reload follow KVO on the webview's
//! `canGoBack`, `canGoForward`, `loading` and `URL`. The download button
//! needs the displayed main-frame response's `Content-Type` and
//! `Content-Disposition`, which only `webView:decidePolicyForNavigationResponse:`
//! sees. That method is reached the way `connect_web_http_auth` reaches the
//! authentication challenge: a forwarding proxy navigation delegate that
//! implements only that one method, records the response and passes the
//! call on to the delegate it wraps (wry's, or the HTTP-auth proxy), which
//! decides as before. Every other selector is forwarded unchanged.
//!
//! **Download.** Never a bypass of `RemotePolicy::on_download` (A6): the
//! click runs the same `web::download_decision` on the shown URL *before*
//! any request is made, a redirect and the final response URL are held to
//! it again, and the response must be 2xx and downloadable (`transfer`). On
//! macOS 11.3+ the document is fetched again by `WKWebView.startDownload(using:)`
//! — the webview's own network session, cookies and proxy — with this
//! module's `WKDownloadDelegate`; on 10.15–11.2 by an ephemeral `URLSession`
//! carrying a copy of the webview's cookies (`path=refetch`). Either way the
//! bytes are counted against the per-window [`DownloadLimiter`] on every
//! report, written to a private staging file and moved over the name
//! `next_free_path` reserved in the Downloads folder (`transfer::DownloadJob`).
//! A server-trust challenge on either route is decided by the window's TLS
//! pin gate exactly as for the page (`connect_web_tls_pin::macos`), without
//! ever asking the operator from here.
//!
//! **Isolation.** Nothing here gives the page a way in: no script is
//! injected or run, and no page-to-host message channel exists (spec §8.1;
//! `test_bar_is_not_a_dom_node`). The page cannot reach an AppKit view.
//!
//! **Threads and lifetimes.** Every native object lives on the main thread
//! in the [`BARS`] registry; the Objective-C side (button target, observers,
//! delegates) holds only integer ids, so there is no reference cycle and a
//! callback after teardown finds nothing. Teardown runs on [`NavBar::detach`]
//! or when the window closes (`NSWindowWillCloseNotification`), whichever is
//! first, removes every observer and the bar view, and cancels in-flight
//! downloads. Objects released from inside one of their own callbacks are
//! released on a later turn of the event loop ([`defer_release`]).
//!
//! **Only compile-verified.** The AppKit / WebKit / Foundation calls below
//! need a running `NSApplication` and a live WKWebView, which unit tests do
//! not have; the decisions they apply are in `model` and `transfer` and are tested there.

mod model;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use block2::{DynBlock, RcBlock};
use objc2::rc::{Retained, Weak};
use objc2::runtime::{AnyClass, AnyObject, NSObject, NSObjectProtocol, ProtocolObject, Sel};
use objc2::{define_class, msg_send, sel, AllocAnyThread, ClassType, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAutoresizingMaskOptions, NSButton, NSCellImagePosition, NSColor, NSImage, NSView, NSVisualEffectBlendingMode,
    NSVisualEffectMaterial, NSVisualEffectState, NSVisualEffectView, NSWindow, NSWindowWillCloseNotification,
};
use objc2_foundation::{
    ns_string, NSArray, NSData, NSDictionary, NSError, NSHTTPCookie, NSHTTPURLResponse, NSKeyValueChangeKey,
    NSKeyValueObservingOptions, NSNotification, NSNotificationCenter, NSObjectNSKeyValueObserverRegistration, NSPoint,
    NSProcessInfo, NSProgress, NSProgressReporting, NSRect, NSSize, NSString, NSURLAuthenticationChallenge,
    NSURLAuthenticationMethodServerTrust, NSURLCredential, NSURLRequest, NSURLResponse, NSURLSession,
    NSURLSessionAuthChallengeDisposition, NSURLSessionConfiguration, NSURLSessionDataDelegate, NSURLSessionDataTask,
    NSURLSessionDelegate, NSURLSessionResponseDisposition, NSURLSessionTask, NSURLSessionTaskDelegate, NSURL,
};
use objc2_web_kit::{
    WKDownload, WKDownloadDelegate, WKDownloadRedirectPolicy, WKNavigationDelegate, WKNavigationResponse,
    WKNavigationResponsePolicy, WKWebView,
};
use tauri::{AppHandle, Url};

use self::model::{DownloadRoute, Frame};
use super::transfer::{self, Destination, MainFrameResponse, ResponseFacts, ResponseTracker, Settled, Transfer};
use super::{mark_operator_reload, reason, DownloadLimiter, DownloadPath, NavAction, NavBar, NavBarAudit, NavState};
use crate::session::web::{OriginSet, WebShared};
use crate::session::web_tls_pin::TlsPinGate;

// ── Public surface ─────────────────────────────────────────────────

/// Who owns the remote webview's frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebviewFrame {
    /// The webview fills its superview through autoresizing (the default
    /// build, where it is the window's content): the shim shrinks it by
    /// `BAR_HEIGHT` once and autoresizing keeps it so.
    ShrinkToFit,
    /// The host sets the webview's bounds itself (the `web_session_chrome`
    /// window's resize handler): the shim only places the bar, and the
    /// host's layout must leave `BAR_HEIGHT` free at the bottom.
    HostManaged,
}

/// What one session window's bar needs. Nothing here is a credential: the
/// bar reads navigation state, the origin set and `allow_downloads` only
/// (spec §8.2).
pub struct NavBarConfig {
    /// The profile's `allow_downloads` (spec §7.4).
    pub allow_downloads: bool,
    /// The window's navigation allow-list (`RemotePolicy::origins`).
    pub origins: Arc<OriginSet>,
    /// The session's audit sink (`connect.web.nav` / `download*`).
    pub audit: NavBarAudit,
    /// The session, for the operator-reload mark (G5).
    pub shared: Arc<WebShared>,
    /// The window's TLS pin gate, so a download's server-trust challenge is
    /// decided exactly as the page's. `None`: platform evaluation only.
    pub tls_pin: Option<Arc<TlsPinGate>>,
    pub frame: WebviewFrame,
}

/// Attach the bar to the session's remote webview. Call it right after the
/// webview is built (`build_window`), from any thread: the native work is
/// queued to the main thread through `with_webview`, ahead of the native
/// handlers' install and of the navigation to the start URL. The returned
/// handle is inert until then, and if the webview is already gone. A bar that
/// cannot be attached leaves the window without one (logged); it is never a
/// policy gate, so nothing else depends on it.
pub fn attach(remote: &tauri::Webview, config: NavBarConfig) -> Box<dyn NavBar> {
    let id = NEXT_BAR.fetch_add(1, Ordering::Relaxed);
    let handle = MacNavBar { id, app: config.audit.app.clone() };
    let context = format!("resource={} token={}", config.audit.resource, config.audit.token);
    let queued = remote.with_webview(move |webview| {
        if let Err(why) = install(id, webview, config) {
            log::warn!("connect.web.nav_bar: not attached: {context} — {why}");
        }
    });
    if let Err(e) = queued {
        log::warn!("connect.web.nav_bar: not attached, the session webview is gone: {e}");
    }
    Box::new(handle)
}

/// The `Send` handle: an id into the main-thread registry.
struct MacNavBar {
    id: u64,
    app: AppHandle,
}

impl MacNavBar {
    /// Run `f` on the main thread (at once when already there).
    fn on_main(&self, f: impl FnOnce() + Send + 'static) {
        if let Err(e) = self.app.run_on_main_thread(f) {
            log::warn!("connect.web.nav_bar: could not reach the main thread: {e}");
        }
    }
}

impl NavBar for MacNavBar {
    /// Render `state` until the next change the shim observes itself (KVO,
    /// a main-frame response), which recomputes it from the webview.
    fn set_state(&self, state: &NavState) {
        let (id, state) = (self.id, state.clone());
        self.on_main(move || {
            with_bar(id, |bar| {
                bar.render(&state);
                *bar.state.borrow_mut() = state;
            });
        });
    }

    fn detach(self: Box<Self>) {
        let id = self.id;
        self.on_main(move || teardown(id));
    }
}

// ── Registry ───────────────────────────────────────────────────────

static NEXT_BAR: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// Main thread only: every live bar, by id.
    static BARS: RefCell<HashMap<u64, Rc<NativeBar>>> = RefCell::new(HashMap::new());
    /// Main thread only: objects waiting for [`defer_release`]'s sweep.
    static DEFERRED: RefCell<Vec<Box<dyn std::any::Any>>> = const { RefCell::new(Vec::new()) };
}

fn bar(id: u64) -> Option<Rc<NativeBar>> {
    BARS.with(|b| b.borrow().get(&id).cloned())
}

/// Run `f` on bar `id` if it is still attached. The registry borrow is
/// released before `f` runs, so `f` may tear the bar down.
fn with_bar<R>(id: u64, f: impl FnOnce(&NativeBar) -> R) -> Option<R> {
    bar(id).map(|b| f(&b))
}

/// Release `item` on a later turn of the main event loop. Teardown and the
/// end of a download run inside callbacks of the objects they release (the
/// notification target, a delegate); dropping the last reference there
/// would deallocate an object while its own method runs. On the main thread
/// `run_on_main_thread` runs at once, so the sweep is queued from the async
/// runtime instead.
fn defer_release(app: &AppHandle, item: Box<dyn std::any::Any>) {
    DEFERRED.with(|d| d.borrow_mut().push(item));
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = app.run_on_main_thread(|| {
            let items = DEFERRED.with(|d| std::mem::take(&mut *d.borrow_mut()));
            drop(items);
        });
    });
}

fn teardown(id: u64) {
    let Some(native) = BARS.with(|b| b.borrow_mut().remove(&id)) else { return };
    native.teardown();
    let app = native.app.clone();
    defer_release(&app, Box::new(native));
}

// ── The bar ────────────────────────────────────────────────────────

/// Button order in the bar (index = position from the left).
const ACTIONS: [NavAction; 4] = [NavAction::Back, NavAction::Forward, NavAction::Reload, NavAction::Download];

/// The WKWebView properties the bar follows (all KVO-compliant).
const KVO_PATHS: [&str; 4] = ["canGoBack", "canGoForward", "loading", "URL"];

/// How long a refused download's message replaces the download tooltip.
const FLASH_FOR: Duration = Duration::from_secs(3);

struct NativeBar {
    id: u64,
    app: AppHandle,
    audit: NavBarAudit,
    allow_downloads: bool,
    origins: Arc<OriginSet>,
    shared: Arc<WebShared>,
    tls_pin: Option<Arc<TlsPinGate>>,
    frame_mode: WebviewFrame,
    route: DownloadRoute,
    limiter: Arc<DownloadLimiter>,
    webview: Retained<WKWebView>,
    container: Retained<NSView>,
    window: Option<Retained<NSWindow>>,
    bar: Retained<NSVisualEffectView>,
    buttons: [Retained<NSButton>; 4],
    target: Retained<NavBarTarget>,
    tracker: RefCell<ResponseTracker>,
    state: RefCell<NavState>,
    flash: Cell<Option<&'static str>>,
    flash_generation: Cell<u64>,
    downloads: RefCell<HashMap<u64, InFlight>>,
    next_download: Cell<u64>,
    torn_down: Cell<bool>,
}

/// One download: its state machine and the native objects driving it.
struct InFlight {
    transfer: Transfer,
    native: Native,
}

enum Native {
    /// `startDownload` / `getAllCookies` has not answered yet.
    Pending,
    WebKit {
        download: Retained<WKDownload>,
        delegate: Retained<DownloadDelegate>,
        progress: Retained<NSProgress>,
        observer: Retained<ProgressObserver>,
    },
    Refetch {
        session: Retained<NSURLSession>,
        task: Retained<NSURLSessionDataTask>,
        delegate: Retained<RefetchDelegate>,
    },
}

impl Native {
    /// Unhook the transfer and, with `cancel`, stop it. Returns the objects
    /// for [`defer_release`].
    fn shut(self, cancel: bool) -> Box<dyn std::any::Any> {
        match self {
            Native::Pending => Box::new(()),
            Native::WebKit { download, delegate, progress, observer } => {
                // SAFETY: removes the observation `webkit_started` added, with
                // the same observer and key path, on the main thread.
                unsafe { progress.removeObserver_forKeyPath(&observer, ns_string!("completedUnitCount")) };
                if cancel {
                    // SAFETY: cancelling a live WKDownload on the main thread;
                    // no resume-data handler.
                    unsafe { download.cancel(None) };
                }
                // SAFETY: clearing the download's weak delegate on the main
                // thread, so WebKit calls nothing on it once it is released.
                unsafe { download.setDelegate(None) };
                Box::new((download, delegate, progress, observer))
            }
            Native::Refetch { session, task, delegate } => {
                if cancel {
                    task.cancel();
                    session.invalidateAndCancel();
                } else {
                    // Lets the session release its delegate once done.
                    session.finishTasksAndInvalidate();
                }
                Box::new((session, task, delegate))
            }
        }
    }
}

fn rect(f: Frame) -> NSRect {
    NSRect::new(NSPoint::new(f.x, f.y), NSSize::new(f.width, f.height))
}

fn frame_of(r: NSRect) -> Frame {
    Frame { x: r.origin.x, y: r.origin.y, width: r.size.width, height: r.size.height }
}

fn to_url(u: &NSURL) -> Option<Url> {
    u.absoluteString().and_then(|s| Url::parse(&s.to_string()).ok())
}

fn file_url(path: &Path) -> Option<Retained<NSURL>> {
    path.to_str().map(|p| NSURL::fileURLWithPath_isDirectory(&NSString::from_str(p), false))
}

fn destination() -> Option<Destination> {
    Some(Destination {
        downloads_dir: transfer::downloads_dir(dirs::download_dir(), dirs::home_dir())?,
        staging_root: std::env::temp_dir(),
    })
}

/// Read what the bar needs out of a response (never logged).
fn response_facts(response: &NSURLResponse, suggested: Option<String>) -> ResponseFacts {
    let http = response.downcast_ref::<NSHTTPURLResponse>();
    ResponseFacts {
        url: response.URL().as_deref().and_then(to_url),
        status: http.map(|h| h.statusCode() as i64),
        mime: response.MIMEType().map(|m| m.to_string()),
        content_disposition: http
            .and_then(|h| h.valueForHTTPHeaderField(ns_string!("Content-Disposition")))
            .map(|v| v.to_string()),
        expected_length: u64::try_from(response.expectedContentLength()).ok(),
        suggested_filename: suggested.or_else(|| response.suggestedFilename().map(|s| s.to_string())),
    }
}

fn action_selector(action: NavAction) -> Sel {
    match action {
        NavAction::Back => sel!(navBarBack:),
        NavAction::Forward => sel!(navBarForward:),
        NavAction::Reload => sel!(navBarReload:),
        NavAction::Download => sel!(navBarDownload:),
    }
}

fn make_button(
    mtm: MainThreadMarker,
    action: NavAction,
    index: usize,
    target: &NavBarTarget,
    symbols: bool,
) -> Retained<NSButton> {
    let (symbol, fallback, label) = model::button_face(action);
    let label = NSString::from_str(label);
    let image = if symbols {
        NSImage::imageWithSystemSymbolName_accessibilityDescription(&NSString::from_str(symbol), Some(&label))
    } else {
        None
    };
    let target: &AnyObject = target;
    // SAFETY: AppKit constructors on the main thread. `target` implements
    // the action selector and outlives the button: the bar keeps it, and
    // teardown clears every button's target before the bar is released.
    let button = unsafe {
        match &image {
            Some(image) => {
                NSButton::buttonWithImage_target_action(image, Some(target), Some(action_selector(action)), mtm)
            }
            None => NSButton::buttonWithTitle_target_action(
                &NSString::from_str(fallback),
                Some(target),
                Some(action_selector(action)),
                mtm,
            ),
        }
    };
    if image.is_some() {
        button.setImagePosition(NSCellImagePosition::ImageOnly);
    }
    button.setBordered(false);
    button.setFrame(rect(model::button_frame(index)));
    button.setToolTip(Some(&label));
    // A click on the bar leaves keyboard focus in the page.
    button.setRefusesFirstResponder(true);
    button.setEnabled(false);
    button
}

/// Build the bar on the main thread (the `with_webview` closure).
fn install(id: u64, webview: tauri::webview::PlatformWebview, config: NavBarConfig) -> Result<(), &'static str> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    // SAFETY: `inner()` is a valid WKWebView, live for this call. We take our
    // own +1 with `retain` rather than adopting tauri's reference: the
    // tauri-runtime-wry versions `tauri = "2"` resolves to differ in whether
    // they pass +1 or +0 (see `connect_web_http_auth`), and `retain` is
    // balanced under both.
    let wk: Option<Retained<WKWebView>> = unsafe { Retained::retain(webview.inner().cast()) };
    let wk = wk.ok_or("the session window has no WKWebView")?;
    // SAFETY: a view-hierarchy read on the main thread.
    let container = unsafe { wk.superview() }.ok_or("the webview is not in a view hierarchy")?;
    let window = wk.window();

    let os = NSProcessInfo::processInfo().operatingSystemVersion();
    let mut route = model::download_route(os.majorVersion, os.minorVersion);
    if route == DownloadRoute::WebKit && !wk.respondsToSelector(sel!(startDownloadUsingRequest:completionHandler:)) {
        route = DownloadRoute::Refetch;
    }

    let flipped = container.isFlipped();
    let (web_frame, bar_frame) = model::split_frames(frame_of(container.bounds()), flipped);
    let target = NavBarTarget::new(mtm, id);
    let bar_view = NSVisualEffectView::initWithFrame(mtm.alloc(), rect(bar_frame));
    bar_view.setMaterial(NSVisualEffectMaterial::Titlebar);
    bar_view.setBlendingMode(NSVisualEffectBlendingMode::WithinWindow);
    bar_view.setState(NSVisualEffectState::FollowsWindowActiveState);
    let margin = if model::bar_flexible_margin_is_max_y(flipped) {
        NSAutoresizingMaskOptions::ViewMaxYMargin
    } else {
        NSAutoresizingMaskOptions::ViewMinYMargin
    };
    bar_view.setAutoresizingMask(NSAutoresizingMaskOptions::ViewWidthSizable | margin);
    let symbols = model::has_sf_symbols(os.majorVersion);
    let buttons: [Retained<NSButton>; 4] = std::array::from_fn(|i| make_button(mtm, ACTIONS[i], i, &target, symbols));
    for button in &buttons {
        bar_view.addSubview(button);
    }
    container.addSubview(&bar_view);
    if config.frame == WebviewFrame::ShrinkToFit {
        wk.setFrame(rect(web_frame));
    }

    let native = Rc::new(NativeBar {
        id,
        app: config.audit.app.clone(),
        audit: config.audit,
        allow_downloads: config.allow_downloads,
        origins: config.origins,
        shared: config.shared,
        tls_pin: config.tls_pin,
        frame_mode: config.frame,
        route,
        limiter: Arc::new(DownloadLimiter::new()),
        webview: wk,
        container,
        window,
        bar: bar_view,
        buttons,
        target,
        tracker: RefCell::new(ResponseTracker::default()),
        state: RefCell::new(NavState { allow_downloads: config.allow_downloads, ..NavState::default() }),
        flash: Cell::new(None),
        flash_generation: Cell::new(0),
        downloads: RefCell::new(HashMap::new()),
        next_download: Cell::new(0),
        torn_down: Cell::new(false),
    });
    BARS.with(|b| b.borrow_mut().insert(id, Rc::clone(&native)));
    native.observe();
    if let Err(why) = install_response_proxy(id, &native.webview, mtm) {
        // Back / forward / reload still work; the download button stays
        // disabled, since nothing tells it what the page is.
        log::warn!("connect.web.nav_bar: downloads unavailable in this window: {why}");
    }
    native.refresh();
    Ok(())
}

impl NativeBar {
    fn observe(&self) {
        for path in KVO_PATHS {
            // SAFETY: registers the bar's target, kept alive by the bar until
            // teardown removes this observation, for a KVO-compliant WKWebView
            // property, on the main thread.
            unsafe {
                self.webview.addObserver_forKeyPath_options_context(
                    &self.target,
                    &NSString::from_str(path),
                    NSKeyValueObservingOptions::New,
                    std::ptr::null_mut(),
                );
            }
        }
        if let Some(window) = &self.window {
            let window: &AnyObject = window;
            // SAFETY: the target implements the selector (one NSNotification
            // argument) and is removed from the centre in teardown before it
            // is released; the object filter is the live session window.
            unsafe {
                NSNotificationCenter::defaultCenter().addObserver_selector_name_object(
                    &self.target,
                    sel!(navBarWindowWillClose:),
                    Some(NSWindowWillCloseNotification),
                    Some(window),
                );
            }
        }
    }

    /// Recompute the state from the webview and render it.
    fn refresh(&self) {
        if self.torn_down.get() {
            return;
        }
        // SAFETY: KVO-compliant property reads on the main thread.
        let (back, forward, loading, shown) = unsafe {
            (self.webview.canGoBack(), self.webview.canGoForward(), self.webview.isLoading(), self.webview.URL())
        };
        let shown = shown.as_deref().and_then(to_url);
        let state = {
            let tracker = self.tracker.borrow();
            transfer::nav_state(back, forward, loading, tracker.for_document(shown.as_ref()), self.allow_downloads)
        };
        self.render(&state);
        *self.state.borrow_mut() = state;
    }

    fn render(&self, state: &NavState) {
        let [back, forward, reload, download] = &self.buttons;
        back.setEnabled(state.can_go_back);
        forward.setEnabled(state.can_go_forward);
        reload.setEnabled(!state.is_loading);
        download.setEnabled(state.download_enabled());
        let (tip, tint) = match self.flash.get() {
            Some(refusal) => (transfer::refusal_message(refusal), Some(NSColor::systemRedColor())),
            None => (transfer::download_tooltip(state), None),
        };
        download.setToolTip(Some(&NSString::from_str(tip)));
        download.setContentTintColor(tint.as_deref());
    }

    /// Show `refusal` on the download button for a few seconds (the
    /// short-lived error state, spec §7.6).
    fn flash(&self, refusal: &'static str) {
        if self.torn_down.get() {
            return;
        }
        let generation = self.flash_generation.get().wrapping_add(1);
        self.flash_generation.set(generation);
        self.flash.set(Some(refusal));
        let state = self.state.borrow().clone();
        self.render(&state);
        let (app, id) = (self.app.clone(), self.id);
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(FLASH_FOR).await;
            let _ = app.run_on_main_thread(move || {
                with_bar(id, |bar| bar.end_flash(generation));
            });
        });
    }

    fn end_flash(&self, generation: u64) {
        if self.flash_generation.get() != generation {
            return;
        }
        self.flash.set(None);
        let state = self.state.borrow().clone();
        self.render(&state);
    }

    /// A button click. Back / forward / reload are audited once each, as
    /// the operator's action: the returned `WKNavigation` is not consulted,
    /// since a same-document history step can come back without one.
    fn on_click(&self, action: NavAction) {
        let state = self.state.borrow().clone();
        match action {
            NavAction::Back if state.can_go_back => {
                // SAFETY: a WKWebView history call on the main thread.
                let _ = unsafe { self.webview.goBack() };
                self.audit.nav(NavAction::Back);
            }
            NavAction::Forward if state.can_go_forward => {
                // SAFETY: a WKWebView history call on the main thread.
                let _ = unsafe { self.webview.goForward() };
                self.audit.nav(NavAction::Forward);
            }
            NavAction::Reload if !state.is_loading => {
                // Binding order (G5): mark before the reload starts, so the
                // fill engine skips the reload's own load.
                mark_operator_reload(&self.shared);
                // SAFETY: a WKWebView reload on the main thread; it is a
                // navigation, so the allow-list and TLS handlers run on it.
                let _ = unsafe { self.webview.reload() };
                self.audit.nav(NavAction::Reload);
            }
            NavAction::Download if state.download_enabled() => self.start_download(),
            _ => {}
        }
    }

    fn download_path(&self) -> DownloadPath {
        match self.route {
            DownloadRoute::WebKit => DownloadPath::Webview,
            DownloadRoute::Refetch => DownloadPath::Refetch,
        }
    }

    fn refuse(&self, refusal: &'static str) {
        self.audit.download_refused(refusal);
        self.flash(refusal);
    }

    /// The download click. Every refusal before the request is audited
    /// and nothing is fetched.
    fn start_download(&self) {
        // SAFETY: a property read on the main thread.
        let shown = unsafe { self.webview.URL() }.as_deref().and_then(to_url);
        let Some(url) = shown else { return self.refuse(reason::UNAVAILABLE) };
        // The same decision the webview's own downloads get (A6), before
        // any byte is requested.
        if let Err(refusal) = transfer::url_policy(self.allow_downloads, &self.origins, &url) {
            return self.refuse(refusal);
        }
        let Some(slot) = self.limiter.try_acquire() else { return self.refuse(reason::TOO_MANY_DOWNLOADS) };
        let Some(dest) = destination() else { return self.refuse(reason::SAVE_IO_ERROR) };
        let Some(ns_url) = NSURL::URLWithString(&NSString::from_str(url.as_str())) else {
            return self.refuse(reason::UNAVAILABLE);
        };
        let id = self.next_download.get().wrapping_add(1);
        self.next_download.set(id);
        self.downloads
            .borrow_mut()
            .insert(id, InFlight { transfer: Transfer::new(slot, dest), native: Native::Pending });
        let request = NSURLRequest::requestWithURL(&ns_url);
        match self.route {
            DownloadRoute::WebKit => self.start_webkit(id, &request),
            DownloadRoute::Refetch => self.start_refetch(id, request),
        }
    }

    /// Audit how download `id` ended and close it (`cancel`: stop the
    /// native transfer too).
    fn settle(&self, id: u64, outcome: Settled, cancel: bool) {
        match outcome {
            Settled::Saved(saved) => {
                self.audit.download_ok(&saved.filename, &saved.mime, saved.bytes, self.download_path())
            }
            Settled::Refused(refusal) => self.refuse(refusal),
        }
        let entry = self.downloads.borrow_mut().remove(&id);
        if let Some(entry) = entry {
            let keep = entry.native.shut(cancel);
            defer_release(&self.app, Box::new((keep, entry.transfer)));
        }
    }

    /// Apply `step` to download `id`; if it settles the transfer, audit and
    /// close it. Returns whether the transfer is still open. `step` is pure
    /// Rust (no Objective-C call), so holding the borrow over it is safe.
    fn step(&self, id: u64, cancel: bool, step: impl FnOnce(&mut Transfer) -> Option<Settled>) -> bool {
        let outcome = {
            let mut downloads = self.downloads.borrow_mut();
            let Some(entry) = downloads.get_mut(&id) else { return false };
            match step(&mut entry.transfer) {
                None => return entry.transfer.is_open(),
                Some(outcome) => outcome,
            }
        };
        self.settle(id, outcome, cancel);
        false
    }

    /// The response arrived; `Some(staging file)` to save into.
    fn begin(&self, id: u64, facts: &ResponseFacts) -> Option<PathBuf> {
        let now = chrono::Local::now().naive_local();
        let mut path = None;
        // The refusal itself stops the native transfer (a nil destination,
        // a cancel disposition), so no extra cancel.
        let open = self.step(id, false, |t| {
            let outcome = t.begin(facts, self.allow_downloads, &self.origins, now);
            path = t.staging_file().map(Path::to_path_buf);
            outcome
        });
        path.filter(|_| open)
    }

    fn redirect(&self, id: u64, to: Option<&Url>) -> bool {
        self.step(id, false, |t| t.redirect(to, self.allow_downloads, &self.origins))
    }

    fn open_writer(&self, id: u64) -> bool {
        self.step(id, true, Transfer::open_writer)
    }

    fn write_chunk(&self, id: u64, bytes: &[u8]) -> bool {
        self.step(id, true, |t| t.write_chunk(bytes))
    }

    fn on_progress(&self, id: u64, total: u64) {
        self.step(id, true, |t| t.record_total(total));
    }

    fn finish(&self, id: u64) {
        self.step(id, false, Transfer::finish);
    }

    fn fail(&self, id: u64, refusal: &'static str, cancel: bool) {
        self.step(id, cancel, |t| t.fail(refusal));
    }

    // ── macOS 11.3+: WKDownload ──

    fn start_webkit(&self, id: u64, request: &NSURLRequest) {
        let bar_id = self.id;
        let block = RcBlock::new(move |download: NonNull<WKDownload>| {
            // SAFETY: WebKit passes a live WKDownload; `retain` takes our own
            // reference.
            let Some(download) = (unsafe { Retained::retain(download.as_ptr()) }) else { return };
            match bar(bar_id) {
                Some(native) => native.webkit_started(id, download),
                // SAFETY: cancelling a live WKDownload on the main thread.
                None => unsafe { download.cancel(None) },
            }
        });
        // SAFETY: main thread; `request` is live for the call and WebKit
        // copies the block, calling it on the main thread.
        unsafe { self.webview.startDownloadUsingRequest_completionHandler(request, &block) };
    }

    fn webkit_started(&self, id: u64, download: Retained<WKDownload>) {
        let open = self.downloads.borrow().get(&id).is_some_and(|e| e.transfer.is_open());
        if !open {
            // SAFETY: cancelling a live WKDownload on the main thread.
            unsafe { download.cancel(None) };
            return;
        }
        let delegate = DownloadDelegate::new(self.target.mtm(), self.id, id);
        // SAFETY: sets the download's weak delegate on the main thread; the
        // bar keeps `delegate` alive until `Native::shut` clears it again.
        unsafe { download.setDelegate(Some(ProtocolObject::from_ref(&*delegate))) };
        let progress = download.progress();
        let observer = ProgressObserver::new(self.id, id, self.app.clone());
        // SAFETY: KVO registration of an observer the bar keeps alive, with
        // `progress`, until `Native::shut` removes it.
        unsafe {
            progress.addObserver_forKeyPath_options_context(
                &observer,
                ns_string!("completedUnitCount"),
                NSKeyValueObservingOptions::New,
                std::ptr::null_mut(),
            );
        }
        if let Some(entry) = self.downloads.borrow_mut().get_mut(&id) {
            entry.native = Native::WebKit { download, delegate, progress, observer };
        }
    }

    // ── macOS 10.15–11.2: URLSession refetch ──

    fn start_refetch(&self, id: u64, request: Retained<NSURLRequest>) {
        // SAFETY: main-thread reads of the webview's configuration objects.
        let store = unsafe { self.webview.configuration().websiteDataStore().httpCookieStore() };
        let bar_id = self.id;
        let block = RcBlock::new(move |cookies: NonNull<NSArray<NSHTTPCookie>>| {
            // SAFETY: WebKit passes an array that is live for this call.
            let cookies = unsafe { cookies.as_ref() };
            if let Some(native) = bar(bar_id) {
                native.refetch_with(id, &request, cookies);
            }
        });
        // SAFETY: main thread; WebKit copies the block and calls it on the
        // main thread.
        unsafe { store.getAllCookies(&block) };
    }

    fn refetch_with(&self, id: u64, request: &NSURLRequest, cookies: &NSArray<NSHTTPCookie>) {
        if !self.downloads.borrow().get(&id).is_some_and(|e| e.transfer.is_open()) {
            return;
        }
        match self.refetch_session(id, request, cookies) {
            Ok(native) => {
                if let Some(entry) = self.downloads.borrow_mut().get_mut(&id) {
                    entry.native = native;
                }
            }
            Err(why) => {
                log::warn!("connect.web.nav_bar: the download could not be started: {why}");
                self.fail(id, reason::TRANSFER_FAILED, false);
            }
        }
    }

    /// An ephemeral session holding a copy of the webview's cookies (the
    /// store matches them to the request itself: domain, path, secure,
    /// expiry), delivering every callback on the main queue. A few calls go
    /// through `msg_send!`: their typed bindings sit behind objc2-foundation
    /// features (`NSHTTPCookieStorage`, `NSOperation`) that nothing in this
    /// graph enables, and enabling them would rebuild the whole AppKit stack.
    ///
    /// Proxy mode (T106) cannot apply here: wry's proxy configuration needs
    /// macOS 14, and this route only runs below 11.3.
    fn refetch_session(
        &self,
        id: u64,
        request: &NSURLRequest,
        cookies: &NSArray<NSHTTPCookie>,
    ) -> Result<Native, &'static str> {
        let config = NSURLSessionConfiguration::ephemeralSessionConfiguration();
        // SAFETY: `-[NSURLSessionConfiguration HTTPCookieStorage]` returns the
        // ephemeral configuration's own in-memory store, or nil.
        let storage: Option<Retained<AnyObject>> = unsafe { msg_send![&*config, HTTPCookieStorage] };
        let storage = storage.ok_or("the session has no cookie store")?;
        // SAFETY: `-[NSHTTPCookieStorage setCookieAcceptPolicy:]` takes an
        // `NSHTTPCookieAcceptPolicy` (NSUInteger); 0 is `Always`, so the
        // copies below are kept.
        let _: () = unsafe { msg_send![&*storage, setCookieAcceptPolicy: 0usize] };
        for cookie in cookies.iter() {
            // SAFETY: `-[NSHTTPCookieStorage setCookie:]` with a live cookie.
            let _: () = unsafe { msg_send![&*storage, setCookie: &*cookie] };
        }
        config.setHTTPShouldSetCookies(true);
        let queue_class = AnyClass::get(c"NSOperationQueue").ok_or("no NSOperationQueue class")?;
        // SAFETY: `+[NSOperationQueue mainQueue]` returns the main queue.
        let main_queue: Option<Retained<AnyObject>> = unsafe { msg_send![queue_class, mainQueue] };
        let main_queue = main_queue.ok_or("no main operation queue")?;
        let delegate = RefetchDelegate::new(self.id, id);
        let delegate_ref: &ProtocolObject<dyn NSURLSessionDelegate> = ProtocolObject::from_ref(&*delegate);
        // SAFETY: `+[NSURLSession sessionWithConfiguration:delegate:delegateQueue:]`
        // with live arguments. The session retains its delegate until it is
        // invalidated (`Native::shut`) and calls it on the main queue, where
        // the bar lives.
        let session: Retained<NSURLSession> = unsafe {
            msg_send![
                NSURLSession::class(),
                sessionWithConfiguration: &*config,
                delegate: delegate_ref,
                delegateQueue: &*main_queue
            ]
        };
        let task = session.dataTaskWithRequest(request);
        task.resume();
        Ok(Native::Refetch { session, task, delegate })
    }

    // ── Teardown ──

    fn teardown(&self) {
        self.torn_down.set(true);
        for path in KVO_PATHS {
            // SAFETY: removes an observation `observe` added (same observer,
            // same key path), on the main thread.
            unsafe { self.webview.removeObserver_forKeyPath(&self.target, &NSString::from_str(path)) };
        }
        // SAFETY: removing the target from the notification centre on the
        // main thread (a no-op when it was never added).
        unsafe { NSNotificationCenter::defaultCenter().removeObserver(&self.target) };
        for button in &self.buttons {
            // SAFETY: clearing the action target on the main thread, so
            // nothing can message the target once it is released.
            unsafe { button.setTarget(None) };
        }
        self.bar.removeFromSuperview();
        // SAFETY: a view-hierarchy read on the main thread.
        let parent = unsafe { self.webview.superview() };
        let same_parent = parent.is_some_and(|p| Retained::as_ptr(&p) == Retained::as_ptr(&self.container));
        if self.frame_mode == WebviewFrame::ShrinkToFit && same_parent {
            self.webview.setFrame(self.container.bounds());
        }
        let ids: Vec<u64> = self.downloads.borrow().keys().copied().collect();
        for id in ids {
            self.fail(id, reason::TRANSFER_FAILED, true);
        }
    }
}

// ── Main-frame responses (forwarding proxy delegate) ───────────────

fn note_response(bar_id: u64, response: &WKNavigationResponse) {
    // SAFETY: property reads on the WKNavigationResponse WebKit passed in,
    // on the main thread.
    let (main_frame, shown, ns_response) =
        unsafe { (response.isForMainFrame(), response.canShowMIMEType(), response.response()) };
    // A response the webview cannot show becomes a download (the webview's
    // own path) or is cancelled: it never becomes the shown document.
    if !main_frame || !shown {
        return;
    }
    let facts = response_facts(&ns_response, None);
    let Some(url) = facts.url else { return };
    let attachment = facts.content_disposition.as_deref().is_some_and(transfer::is_attachment);
    with_bar(bar_id, |native| {
        native.tracker.borrow_mut().record(MainFrameResponse { url, mime: facts.mime, attachment });
        native.refresh();
    });
}

struct ProxyIvars {
    bar: u64,
    /// The delegate this proxy wraps (wry's, or the HTTP-auth proxy). Weak:
    /// it owns the proxy.
    inner: Weak<ProtocolObject<dyn WKNavigationDelegate>>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; the class adds no
    // `dealloc` and its ivars are plain Rust values dropped by objc2.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "BastionVaultNavBarResponseDelegate"]
    #[ivars = ProxyIvars]
    struct ResponseProxy;

    impl ResponseProxy {
        /// Ours, or anything the wrapped delegate answers.
        // SAFETY: the signature matches `-[NSObject respondsToSelector:]`.
        #[unsafe(method(respondsToSelector:))]
        fn responds_to_selector(&self, selector: Sel) -> bool {
            // SAFETY: `super` is NSObject, which implements the method.
            let own: bool = unsafe { msg_send![super(self), respondsToSelector: selector] };
            own || self.ivars().inner.load().is_some_and(|inner| inner.respondsToSelector(selector))
        }

        /// Re-send everything the proxy does not implement to the wrapped
        /// delegate, which then runs with its own `self`. Autoreleased (+0),
        /// as the runtime expects.
        // SAFETY: the signature matches `-[NSObject forwardingTargetForSelector:]`.
        #[unsafe(method(forwardingTargetForSelector:))]
        fn forwarding_target(&self, _selector: Sel) -> *mut AnyObject {
            match self.ivars().inner.load() {
                Some(inner) => Retained::autorelease_ptr(inner).cast(),
                None => std::ptr::null_mut(),
            }
        }
    }

    // SAFETY: NSObjectProtocol has no requirements beyond NSObject's.
    unsafe impl NSObjectProtocol for ResponseProxy {}

    // SAFETY: the one method below has the signature WebKit declares for it
    // (`objc2_web_kit::WKNavigationDelegate`).
    unsafe impl WKNavigationDelegate for ResponseProxy {
        /// Record the response, then let the wrapped delegate decide it.
        #[unsafe(method(webView:decidePolicyForNavigationResponse:decisionHandler:))]
        fn decide_response(
            &self,
            web_view: &WKWebView,
            response: &WKNavigationResponse,
            handler: &DynBlock<dyn Fn(WKNavigationResponsePolicy)>,
        ) {
            note_response(self.ivars().bar, response);
            let selector = sel!(webView:decidePolicyForNavigationResponse:decisionHandler:);
            match self.ivars().inner.load() {
                Some(inner) if inner.respondsToSelector(selector) => {
                    // SAFETY: `inner` answers the selector (checked above),
                    // which takes (WKWebView *, WKNavigationResponse *,
                    // void (^)(WKNavigationResponsePolicy)) and returns void;
                    // every argument is the one WebKit passed in, so the
                    // handler is called exactly once, by `inner`.
                    unsafe {
                        let _: () = msg_send![
                            &*inner,
                            webView: web_view,
                            decidePolicyForNavigationResponse: response,
                            decisionHandler: handler
                        ];
                    }
                }
                _ => {
                    // What WebKit does for a delegate without the method:
                    // show what it can show, cancel the rest.
                    // SAFETY: a property read on the main thread.
                    let policy = if unsafe { response.canShowMIMEType() } {
                        WKNavigationResponsePolicy::Allow
                    } else {
                        WKNavigationResponsePolicy::Cancel
                    };
                    handler.call((policy,));
                }
            }
        }
    }
);

/// Key for the associated object; only its address matters.
static RESPONSE_PROXY_KEY: u8 = 0;

/// Wrap the webview's current navigation delegate in a [`ResponseProxy`].
/// Lifetimes as in `connect_web_http_auth`: WKWebView holds its delegate
/// weakly, so the proxy is retained as an associated object of the delegate
/// it wraps and holds that delegate weakly. It stays in the chain after
/// teardown (a later wrapper may hold it as its own inner), inert: its bar
/// id no longer resolves.
fn install_response_proxy(bar_id: u64, wk: &WKWebView, mtm: MainThreadMarker) -> Result<(), &'static str> {
    // SAFETY: a plain property read on the main thread.
    let inner = unsafe { wk.navigationDelegate() }.ok_or("the webview has no navigation delegate to extend")?;
    let proxy = mtm.alloc::<ResponseProxy>().set_ivars(ProxyIvars { bar: bar_id, inner: Weak::from_retained(&inner) });
    // SAFETY: `init` on a freshly allocated NSObject subclass.
    let proxy: Retained<ResponseProxy> = unsafe { msg_send![super(proxy), init] };
    // SAFETY: both pointers are live objects; the key is a static address;
    // RETAIN_NONATOMIC makes the wrapped delegate own the proxy (released
    // with it). Main thread, like every other use.
    unsafe {
        objc2::ffi::objc_setAssociatedObject(
            Retained::as_ptr(&inner).cast_mut().cast(),
            std::ptr::addr_of!(RESPONSE_PROXY_KEY).cast::<c_void>(),
            Retained::as_ptr(&proxy).cast_mut().cast(),
            objc2::ffi::OBJC_ASSOCIATION_RETAIN_NONATOMIC,
        );
    }
    // SAFETY: sets the weak delegate property on the main thread, to an
    // object kept alive by the association above. WebKit reads which
    // optional methods a delegate implements when it is set; the proxy is
    // complete by now.
    unsafe { wk.setNavigationDelegate(Some(ProtocolObject::from_ref(&*proxy))) };
    Ok(())
}

// ── Button target, KVO and window-close observer ───────────────────

struct TargetIvars {
    bar: u64,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; the class adds no
    // `dealloc` and its ivar is an integer.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "BastionVaultNavBarTarget"]
    #[ivars = TargetIvars]
    struct NavBarTarget;

    impl NavBarTarget {
        // SAFETY (the four actions): `- (void)name:(id)sender`, the shape
        // NSControl sends.
        #[unsafe(method(navBarBack:))]
        fn back(&self, _sender: Option<&AnyObject>) {
            with_bar(self.ivars().bar, |bar| bar.on_click(NavAction::Back));
        }

        #[unsafe(method(navBarForward:))]
        fn forward(&self, _sender: Option<&AnyObject>) {
            with_bar(self.ivars().bar, |bar| bar.on_click(NavAction::Forward));
        }

        #[unsafe(method(navBarReload:))]
        fn reload(&self, _sender: Option<&AnyObject>) {
            with_bar(self.ivars().bar, |bar| bar.on_click(NavAction::Reload));
        }

        #[unsafe(method(navBarDownload:))]
        fn download(&self, _sender: Option<&AnyObject>) {
            with_bar(self.ivars().bar, |bar| bar.on_click(NavAction::Download));
        }

        /// `NSWindowWillCloseNotification` for the session window.
        // SAFETY: a notification selector takes one NSNotification.
        #[unsafe(method(navBarWindowWillClose:))]
        fn window_will_close(&self, _note: &NSNotification) {
            teardown(self.ivars().bar);
        }

        /// KVO on the webview's [`KVO_PATHS`].
        // SAFETY: the signature of `-[NSObject observeValueForKeyPath:ofObject:change:context:]`.
        #[unsafe(method(observeValueForKeyPath:ofObject:change:context:))]
        fn observe_value(
            &self,
            _key_path: Option<&NSString>,
            _object: Option<&AnyObject>,
            _change: Option<&NSDictionary<NSKeyValueChangeKey, AnyObject>>,
            _context: *mut c_void,
        ) {
            with_bar(self.ivars().bar, |bar| bar.refresh());
        }
    }

    // SAFETY: NSObjectProtocol has no requirements beyond NSObject's.
    unsafe impl NSObjectProtocol for NavBarTarget {}
);

impl NavBarTarget {
    fn new(mtm: MainThreadMarker, bar: u64) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(TargetIvars { bar });
        // SAFETY: `init` on a freshly allocated NSObject subclass.
        unsafe { msg_send![super(this), init] }
    }
}

// ── Download delegates ─────────────────────────────────────────────

type ChallengeCompletion = DynBlock<dyn Fn(NSURLSessionAuthChallengeDisposition, *mut NSURLCredential)>;

/// A download's authentication challenge. Server trust goes to the window's
/// TLS pin gate exactly as the page's does (never asking the operator from
/// here: an unanswered question cancels); everything else, and server trust
/// without a gate, gets the platform's default handling — what WebKit gives
/// the webview's own downloads. A challenge for a torn-down bar is cancelled.
fn answer_challenge(bar_id: u64, challenge: &NSURLAuthenticationChallenge, completion: &ChallengeCompletion) {
    let Some(gate) = with_bar(bar_id, |bar| bar.tls_pin.clone()) else {
        completion.call((NSURLSessionAuthChallengeDisposition::CancelAuthenticationChallenge, std::ptr::null_mut()));
        return;
    };
    // SAFETY: reading Foundation's immutable NSString constant.
    let server_trust = challenge
        .protectionSpace()
        .authenticationMethod()
        .isEqualToString(unsafe { NSURLAuthenticationMethodServerTrust });
    match gate {
        Some(gate) if server_trust => {
            crate::commands::connect_web_tls_pin::macos::server_trust(challenge, &gate, None, completion)
        }
        _ => completion.call((NSURLSessionAuthChallengeDisposition::PerformDefaultHandling, std::ptr::null_mut())),
    }
}

struct DownloadIvars {
    bar: u64,
    download: u64,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; the class adds no
    // `dealloc` and its ivars are integers.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "BastionVaultNavBarDownloadDelegate"]
    #[ivars = DownloadIvars]
    struct DownloadDelegate;

    // SAFETY: NSObjectProtocol has no requirements beyond NSObject's.
    unsafe impl NSObjectProtocol for DownloadDelegate {}

    // SAFETY: every method below has the signature WebKit declares for it
    // (`objc2_web_kit::WKDownloadDelegate`); each completion handler is
    // called exactly once.
    unsafe impl WKDownloadDelegate for DownloadDelegate {
        #[unsafe(method(download:decideDestinationUsingResponse:suggestedFilename:completionHandler:))]
        fn decide_destination(
            &self,
            _download: &WKDownload,
            response: &NSURLResponse,
            suggested_filename: &NSString,
            completion: &DynBlock<dyn Fn(*mut NSURL)>,
        ) {
            let facts = response_facts(response, Some(suggested_filename.to_string()));
            let (bar_id, id) = (self.ivars().bar, self.ivars().download);
            let target = with_bar(bar_id, |bar| bar.begin(id, &facts)).flatten();
            match target.as_deref().and_then(file_url) {
                Some(url) => completion.call((Retained::as_ptr(&url).cast_mut(),)),
                // A nil destination cancels the download.
                None => completion.call((std::ptr::null_mut(),)),
            }
        }

        #[unsafe(method(download:willPerformHTTPRedirection:newRequest:decisionHandler:))]
        fn will_redirect(
            &self,
            _download: &WKDownload,
            _response: &NSHTTPURLResponse,
            request: &NSURLRequest,
            decision: &DynBlock<dyn Fn(WKDownloadRedirectPolicy)>,
        ) {
            let to = request.URL().as_deref().and_then(to_url);
            let (bar_id, id) = (self.ivars().bar, self.ivars().download);
            let allow = with_bar(bar_id, |bar| bar.redirect(id, to.as_ref())).unwrap_or(false);
            decision.call((if allow { WKDownloadRedirectPolicy::Allow } else { WKDownloadRedirectPolicy::Cancel },));
        }

        #[unsafe(method(download:didReceiveAuthenticationChallenge:completionHandler:))]
        fn challenge(
            &self,
            _download: &WKDownload,
            challenge: &NSURLAuthenticationChallenge,
            completion: &ChallengeCompletion,
        ) {
            answer_challenge(self.ivars().bar, challenge, completion);
        }

        #[unsafe(method(downloadDidFinish:))]
        fn did_finish(&self, _download: &WKDownload) {
            let (bar_id, id) = (self.ivars().bar, self.ivars().download);
            with_bar(bar_id, |bar| bar.finish(id));
        }

        /// The error is not logged: its description can carry the URL.
        #[unsafe(method(download:didFailWithError:resumeData:))]
        fn did_fail(&self, _download: &WKDownload, _error: &NSError, _resume_data: Option<&NSData>) {
            let (bar_id, id) = (self.ivars().bar, self.ivars().download);
            with_bar(bar_id, |bar| bar.fail(id, reason::TRANSFER_FAILED, false));
        }
    }
);

impl DownloadDelegate {
    fn new(mtm: MainThreadMarker, bar: u64, download: u64) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(DownloadIvars { bar, download });
        // SAFETY: `init` on a freshly allocated NSObject subclass.
        unsafe { msg_send![super(this), init] }
    }
}

struct ProgressIvars {
    bar: u64,
    download: u64,
    app: AppHandle,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; the class adds no
    // `dealloc` and its ivars are Send + Sync Rust values, so it may be
    // messaged from any thread (NSProgress reports from WebKit's).
    #[unsafe(super(NSObject))]
    #[name = "BastionVaultNavBarProgressObserver"]
    #[ivars = ProgressIvars]
    struct ProgressObserver;

    impl ProgressObserver {
        /// KVO on a WKDownload's `progress.completedUnitCount`: every report
        /// is counted against the soft cap on the main thread.
        // SAFETY: the signature of `-[NSObject observeValueForKeyPath:ofObject:change:context:]`.
        #[unsafe(method(observeValueForKeyPath:ofObject:change:context:))]
        fn observe_value(
            &self,
            _key_path: Option<&NSString>,
            object: Option<&AnyObject>,
            _change: Option<&NSDictionary<NSKeyValueChangeKey, AnyObject>>,
            _context: *mut c_void,
        ) {
            let Some(progress) = object.and_then(|o| o.downcast_ref::<NSProgress>()) else { return };
            let total = u64::try_from(progress.completedUnitCount()).unwrap_or(0);
            let (bar_id, id) = (self.ivars().bar, self.ivars().download);
            let _ = self.ivars().app.run_on_main_thread(move || {
                with_bar(bar_id, |bar| bar.on_progress(id, total));
            });
        }
    }

    // SAFETY: NSObjectProtocol has no requirements beyond NSObject's.
    unsafe impl NSObjectProtocol for ProgressObserver {}
);

impl ProgressObserver {
    fn new(bar: u64, download: u64, app: AppHandle) -> Retained<Self> {
        let this = Self::alloc().set_ivars(ProgressIvars { bar, download, app });
        // SAFETY: `init` on a freshly allocated NSObject subclass.
        unsafe { msg_send![super(this), init] }
    }
}

struct RefetchIvars {
    bar: u64,
    download: u64,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; the class adds no
    // `dealloc` and its ivars are integers. Its session delivers every
    // callback on the main queue (`refetch_session`); off the main thread
    // the registry lookups find nothing and the transfer is cancelled.
    #[unsafe(super(NSObject))]
    #[name = "BastionVaultNavBarRefetchDelegate"]
    #[ivars = RefetchIvars]
    struct RefetchDelegate;

    // SAFETY: NSObjectProtocol has no requirements beyond NSObject's.
    unsafe impl NSObjectProtocol for RefetchDelegate {}

    // SAFETY: the method below has the signature Foundation declares
    // (`objc2_foundation::NSURLSessionDelegate`).
    unsafe impl NSURLSessionDelegate for RefetchDelegate {
        #[unsafe(method(URLSession:didReceiveChallenge:completionHandler:))]
        fn session_challenge(
            &self,
            _session: &NSURLSession,
            challenge: &NSURLAuthenticationChallenge,
            completion: &ChallengeCompletion,
        ) {
            answer_challenge(self.ivars().bar, challenge, completion);
        }
    }

    // SAFETY: every method below has the signature Foundation declares
    // (`objc2_foundation::NSURLSessionTaskDelegate`); each completion handler
    // is called exactly once.
    unsafe impl NSURLSessionTaskDelegate for RefetchDelegate {
        #[unsafe(method(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:))]
        fn will_redirect(
            &self,
            _session: &NSURLSession,
            _task: &NSURLSessionTask,
            _response: &NSHTTPURLResponse,
            request: &NSURLRequest,
            completion: &DynBlock<dyn Fn(*mut NSURLRequest)>,
        ) {
            let to = request.URL().as_deref().and_then(to_url);
            let (bar_id, id) = (self.ivars().bar, self.ivars().download);
            let allow = with_bar(bar_id, |bar| bar.redirect(id, to.as_ref())).unwrap_or(false);
            // A nil request refuses the redirect; the task then completes
            // with the redirect response, which the response check refuses.
            let next = if allow { std::ptr::from_ref(request).cast_mut() } else { std::ptr::null_mut() };
            completion.call((next,));
        }

        #[unsafe(method(URLSession:task:didReceiveChallenge:completionHandler:))]
        fn task_challenge(
            &self,
            _session: &NSURLSession,
            _task: &NSURLSessionTask,
            challenge: &NSURLAuthenticationChallenge,
            completion: &ChallengeCompletion,
        ) {
            answer_challenge(self.ivars().bar, challenge, completion);
        }

        /// The error is not logged: its description can carry the URL.
        #[unsafe(method(URLSession:task:didCompleteWithError:))]
        fn did_complete(&self, _session: &NSURLSession, _task: &NSURLSessionTask, error: Option<&NSError>) {
            let (bar_id, id) = (self.ivars().bar, self.ivars().download);
            with_bar(bar_id, |bar| match error {
                None => bar.finish(id),
                Some(_) => bar.fail(id, reason::TRANSFER_FAILED, false),
            });
        }
    }

    // SAFETY: every method below has the signature Foundation declares
    // (`objc2_foundation::NSURLSessionDataDelegate`); the completion handler
    // is called exactly once.
    unsafe impl NSURLSessionDataDelegate for RefetchDelegate {
        #[unsafe(method(URLSession:dataTask:didReceiveResponse:completionHandler:))]
        fn did_receive_response(
            &self,
            _session: &NSURLSession,
            _task: &NSURLSessionDataTask,
            response: &NSURLResponse,
            completion: &DynBlock<dyn Fn(NSURLSessionResponseDisposition)>,
        ) {
            let facts = response_facts(response, None);
            let (bar_id, id) = (self.ivars().bar, self.ivars().download);
            let accept =
                with_bar(bar_id, |bar| bar.begin(id, &facts).is_some() && bar.open_writer(id)).unwrap_or(false);
            let disposition =
                if accept { NSURLSessionResponseDisposition::Allow } else { NSURLSessionResponseDisposition::Cancel };
            completion.call((disposition,));
        }

        #[unsafe(method(URLSession:dataTask:didReceiveData:))]
        fn did_receive_data(&self, _session: &NSURLSession, task: &NSURLSessionDataTask, data: &NSData) {
            let (bar_id, id) = (self.ivars().bar, self.ivars().download);
            let keep = with_bar(bar_id, |bar| bar.write_chunk(id, &data.to_vec())).unwrap_or(false);
            if !keep {
                task.cancel();
            }
        }
    }
);

impl RefetchDelegate {
    fn new(bar: u64, download: u64) -> Retained<Self> {
        let this = Self::alloc().set_ivars(RefetchIvars { bar, download });
        // SAFETY: `init` on a freshly allocated NSObject subclass.
        unsafe { msg_send![super(this), init] }
    }
}

#[cfg(test)]
mod tests {
    /// The bar is native AppKit, never DOM (spec §7.2, §8.1): neither half of
    /// the shim may inject a script into the page, run one, or open a
    /// page-to-host message channel. The names are assembled from pieces so
    /// this file does not contain them itself.
    #[test]
    fn test_bar_is_not_a_dom_node() {
        let forbidden = [
            concat!("WKUser", "Script"),
            concat!("addUser", "Script"),
            concat!("evaluate", "JavaScript"),
            concat!("WKScript", "MessageHandler"),
        ];
        let sources = [
            ("macos.rs", include_str!("macos.rs")),
            ("macos/model.rs", include_str!("macos/model.rs")),
            ("transfer.rs", include_str!("transfer.rs")),
        ];
        for (name, src) in sources {
            for f in forbidden {
                assert!(!src.contains(f), "{name} uses {f}: the bar must stay a native view (spec §7.2, §8.1)");
            }
        }
    }
}
