//! Linux shim for the web session nav bar: a native GTK 3 strip with back,
//! forward, reload and download at the bottom of the session window
//! (docs/specs/2026-10-20-web-session-nav-controls-design.md §6, §7, §8).
//!
//! **Layout.** wry packs the WebKitGTK webview into the window's vertical
//! `GtkBox` (tao's `default_vbox`) with `pack_start(expand)`, in the default
//! build and in the `web_session_chrome` one alike. The bar is a horizontal
//! `GtkBox` packed at the *end* of that same box, not expanding, with a
//! 36 px size request, so GTK gives it the bottom strip and the webview the
//! rest on every resize. Nothing of wry's is removed, re-parented or
//! disconnected. The buttons take no keyboard focus: a click leaves it in the
//! page.
//!
//! **State.** Back, forward and reload follow the webview's `is-loading` and
//! `uri` notifications, `load-changed` and the back-forward list's `changed`.
//! The download button needs the shown main-frame response's `Content-Type`
//! and `Content-Disposition`: at `LOAD_COMMITTED` the webview's main
//! resource carries that response, and it is recorded in the shared
//! `transfer::ResponseTracker` (page-cache back / forward commits too).
//!
//! **Download.** Never a bypass of `RemotePolicy::on_download` (A6): the
//! click runs the same `web::download_decision` on the shown URL *before*
//! anything is requested (`transfer::url_policy`), then asks WebKitGTK to
//! fetch the document again with `webkit_web_view_download_uri`, in the
//! webview's own web context (its cookies, proxy, TLS policy and the
//! certificate exceptions the pin gate recorded). The response must pass
//! `transfer::check_response` (final URL in the allow-list, 2xx,
//! downloadable, announced size) before a byte is written; a POST result or
//! a one-time link that does not come back is refused as `unavailable`. This
//! is the `path=refetch` route of spec §6 / §7.6 (no MOTW mechanism exists
//! on Linux).
//!
//! wry attaches `RemotePolicy::on_download` to *every* download of the
//! context, in the context's `download-started`. The bar therefore claims
//! the WebKitDownload `download_uri` returns before WebKitGTK announces it:
//! its own `decide-destination` handler is connected first and always
//! returns `TRUE` (the signal's accumulator then stops wry's), and its
//! `failed` / `finished` handlers stop the emission, so wry's never run for
//! it. One download, one owner: one audit line, one file, one limiter slot.
//! If WebKitGTK ever announced the download during the call, the bar would
//! not be first, and it refuses and cancels the download instead
//! (`linux_model::claim`). Downloads the webview escalates by itself (a
//! navigation answered with `Content-Disposition: attachment` or a type it
//! cannot show) are not the bar's: they stay on wry's path and
//! `RemotePolicy::on_download`, as before this change.
//!
//! The bytes are counted against the per-window [`DownloadLimiter`] on every
//! `received-data`, written by WebKitGTK to a private staging file and moved
//! over the name `next_free_path` reserved in the Downloads folder
//! (`transfer::DownloadJob`).
//!
//! **Isolation.** Nothing here gives the page a way in: no script is
//! injected or run, and no page-to-host message channel exists (spec §8.1;
//! `linux_model::tests::test_bar_is_not_a_dom_node`). The page cannot reach
//! a GTK widget. There is no `unsafe` in this file: every GTK / WebKitGTK
//! call goes through the safe gtk-rs / webkit2gtk-rs bindings.
//!
//! **Threads and lifetimes.** GTK and WebKitGTK are main-thread only, and so
//! is everything here: `install` runs in the `with_webview` closure, every
//! signal is emitted on the GTK main context, timers and deferred releases
//! are main-context sources, and the `Send` [`NavBar`] handle reaches the
//! main thread through `AppHandle::run_on_main_thread`. Native objects live
//! in the [`BARS`] registry; signal closures capture integer ids only, so
//! there is no reference cycle and a signal after teardown finds nothing.
//! Teardown runs on [`NavBar::detach`] or when the bar or the webview is
//! destroyed, whichever is first, disconnects every handler it connected on
//! the webview, its context, its back-forward list and the bar's widgets,
//! removes the bar and cancels in-flight downloads. A claimed download keeps
//! its own handlers until WebKitGTK reports it `finished`, so wry's handlers
//! never see it even after teardown; they are disconnected then.
//!
//! **Only compile-verified.** The GTK / WebKitGTK calls below need a display
//! and a live WebKitWebView, which unit tests do not have; the decisions
//! they apply are in `linux_model` and `transfer` and are tested there.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use gtk::glib::{self, SignalHandlerId};
use gtk::prelude::*;
use tauri::{AppHandle, Url};
use webkit2gtk::{DownloadExt, LoadEvent, URIResponseExt, WebContextExt, WebResourceExt, WebViewExt};

use super::linux_model::{self, ACTIONS};
use super::transfer::{self, Destination, ResponseFacts, ResponseTracker, Settled, Transfer};
use super::{
    mark_operator_reload, reason, DownloadLimiter, DownloadPath, NavAction, NavBar, NavBarAudit, NavBarConfig, NavState,
};
use crate::session::web::{OriginSet, WebShared};

// ── Public surface ─────────────────────────────────────────────────

/// Attach the bar to the session's remote webview. Same contract as
/// `macos::attach`: call it right after the webview is built
/// (`build_window`), from any thread. The native work is queued to the main
/// thread through `with_webview`, ahead of the native handlers' install and
/// of the navigation to the start URL. The returned handle is inert until
/// then, and if the webview is already gone. A bar that cannot be attached
/// leaves the window without one (logged); it is never a policy gate, so
/// nothing else depends on it.
///
/// `config.tls_pin` and `config.frame` are not used here (see
/// [`NavBarConfig`]).
pub fn attach(remote: &tauri::Webview, config: NavBarConfig) -> Box<dyn NavBar> {
    let id = NEXT_BAR.fetch_add(1, Ordering::Relaxed);
    let handle = GtkNavBar { id, app: config.audit.app.clone() };
    let context = format!("resource={} token={}", config.audit.resource, config.audit.token);
    let queued = remote.with_webview(move |webview| {
        if let Err(why) = install(id, &webview.inner(), config) {
            log::warn!("connect.web.nav_bar: not attached: {context} — {why}");
        }
    });
    if let Err(e) = queued {
        log::warn!("connect.web.nav_bar: not attached, the session webview is gone: {e}");
    }
    Box::new(handle)
}

/// The `Send` handle: an id into the main-thread registry.
struct GtkNavBar {
    id: u64,
    app: AppHandle,
}

impl GtkNavBar {
    /// Run `f` on the GTK main thread (at once when already there).
    fn on_main(&self, f: impl FnOnce() + Send + 'static) {
        if let Err(e) = self.app.run_on_main_thread(f) {
            log::warn!("connect.web.nav_bar: could not reach the main thread: {e}");
        }
    }
}

impl NavBar for GtkNavBar {
    /// Render `state` until the next change the shim observes itself (a
    /// notification, a load event), which recomputes it from the webview.
    fn set_state(&self, state: &NavState) {
        let (id, state) = (self.id, state.clone());
        self.on_main(move || {
            with_bar(id, |bar| {
                bar.render(&state);
                *bar.state.borrow_mut() = state;
            });
        });
    }

    /// Idempotent: a bar already torn down (window destroyed) is not found.
    fn detach(self: Box<Self>) {
        let id = self.id;
        self.on_main(move || teardown(id));
    }
}

// ── Registry ───────────────────────────────────────────────────────

static NEXT_BAR: AtomicU64 = AtomicU64::new(1);
/// Download ids are unique across bars: a claim outlives its bar.
static NEXT_DOWNLOAD: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// GTK main thread only: every live bar, by id.
    static BARS: RefCell<HashMap<u64, Rc<NativeBar>>> = RefCell::new(HashMap::new());
    /// GTK main thread only: the bar's downloads WebKitGTK has not reported
    /// `finished` yet, with the handlers that keep wry's off them.
    static CLAIMS: RefCell<HashMap<u64, Claim>> = RefCell::new(HashMap::new());
}

fn bar(id: u64) -> Option<Rc<NativeBar>> {
    BARS.with(|b| b.borrow().get(&id).cloned())
}

/// Run `f` on bar `id` if it is still attached. The registry borrow is
/// released before `f` runs, so `f` may tear the bar down.
fn with_bar<R>(id: u64, f: impl FnOnce(&NativeBar) -> R) -> Option<R> {
    bar(id).map(|b| f(&b))
}

fn teardown(id: u64) {
    let Some(native) = BARS.with(|b| b.borrow_mut().remove(&id)) else { return };
    native.teardown();
    // Released on a later turn of the main loop: teardown can run inside a
    // signal handler of a widget `native` holds the last reference to.
    glib::idle_add_local_once(move || drop(native));
}

// ── The bar ────────────────────────────────────────────────────────

/// How long a refused download's message replaces the download tooltip.
const FLASH_FOR: Duration = Duration::from_secs(3);

/// Adwaita's style class for a destructive action (drawn red): the
/// short-lived error state of the download button.
const ALERT_CLASS: &str = "destructive-action";

struct NativeBar {
    id: u64,
    audit: NavBarAudit,
    allow_downloads: bool,
    origins: Arc<OriginSet>,
    shared: Arc<WebShared>,
    limiter: Arc<DownloadLimiter>,
    webview: webkit2gtk::WebView,
    container: gtk::Box,
    bar: gtk::Box,
    buttons: [gtk::Button; 4],
    /// Every handler `connect` made on an object other than a download,
    /// disconnected at teardown.
    handlers: RefCell<Vec<(glib::Object, SignalHandlerId)>>,
    tracker: RefCell<ResponseTracker>,
    state: RefCell<NavState>,
    flash: Cell<Option<&'static str>>,
    flash_generation: Cell<u64>,
    downloads: RefCell<HashMap<u64, InFlight>>,
    /// True while `webkit_web_view_download_uri` runs (the claim guard).
    claiming: Cell<bool>,
    /// Downloads the context announced while `claiming`.
    announced: RefCell<Vec<webkit2gtk::Download>>,
    torn_down: Cell<bool>,
}

/// One of the bar's downloads that has not settled yet.
struct InFlight {
    transfer: Transfer,
    /// `None` until `download_uri` returned it.
    download: Option<webkit2gtk::Download>,
}

/// A claimed download and the handlers connected on it.
struct Claim {
    download: webkit2gtk::Download,
    handlers: Vec<SignalHandlerId>,
}

fn destination() -> Option<Destination> {
    Some(Destination {
        downloads_dir: linux_model::ensure_downloads_dir(dirs::download_dir(), dirs::home_dir())?,
        staging_root: linux_model::staging_root(dirs::cache_dir(), std::env::temp_dir()),
    })
}

fn make_button(action: NavAction) -> gtk::Button {
    let (icon, label) = linux_model::button_face(action);
    let button = gtk::Button::from_icon_name(Some(icon), gtk::IconSize::Button);
    button.set_relief(gtk::ReliefStyle::None);
    button.set_size_request(linux_model::BUTTON_WIDTH_PX, linux_model::BAR_HEIGHT_PX);
    button.set_tooltip_text(Some(label));
    // A click leaves keyboard focus in the page, and Tab never stops here.
    button.set_focus_on_click(false);
    button.set_can_focus(false);
    button.set_sensitive(false);
    button
}

/// Build the bar on the main thread (the `with_webview` closure).
fn install(id: u64, webview: &webkit2gtk::WebView, config: NavBarConfig) -> Result<(), &'static str> {
    if !gtk::is_initialized_main_thread() {
        return Err("not on the GTK main thread");
    }
    let container =
        webview.parent().and_then(|p| p.downcast::<gtk::Box>().ok()).ok_or("the webview is not packed in a GtkBox")?;
    if container.orientation() != gtk::Orientation::Vertical {
        return Err("the webview's box is not vertical");
    }
    let context = webview.context().ok_or("the webview has no web context")?;

    let bar_view = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    bar_view.set_size_request(-1, linux_model::BAR_HEIGHT_PX);
    bar_view.set_vexpand(false);
    let buttons: [gtk::Button; 4] = std::array::from_fn(|i| make_button(ACTIONS[i]));
    for button in &buttons {
        bar_view.pack_start(button, false, false, 0);
    }
    container.pack_end(&bar_view, false, false, 0);
    bar_view.show_all();

    let native = Rc::new(NativeBar {
        id,
        audit: config.audit,
        allow_downloads: config.allow_downloads,
        origins: config.origins,
        shared: config.shared,
        limiter: Arc::new(DownloadLimiter::new()),
        webview: webview.clone(),
        container,
        bar: bar_view,
        buttons,
        handlers: RefCell::new(Vec::new()),
        tracker: RefCell::new(ResponseTracker::default()),
        state: RefCell::new(NavState { allow_downloads: config.allow_downloads, ..NavState::default() }),
        flash: Cell::new(None),
        flash_generation: Cell::new(0),
        downloads: RefCell::new(HashMap::new()),
        claiming: Cell::new(false),
        announced: RefCell::new(Vec::new()),
        torn_down: Cell::new(false),
    });
    BARS.with(|b| b.borrow_mut().insert(id, Rc::clone(&native)));
    native.connect(&context);
    // The page loaded before the bar existed (the start URL loads after this
    // closure, but a reused webview may not).
    native.note_main_resource();
    native.refresh();
    Ok(())
}

impl NativeBar {
    fn keep(&self, object: &impl IsA<glib::Object>, handler: SignalHandlerId) {
        self.handlers.borrow_mut().push((object.clone().upcast(), handler));
    }

    fn connect(&self, context: &webkit2gtk::WebContext) {
        let id = self.id;
        let web = &self.webview;
        self.keep(
            web,
            web.connect_is_loading_notify(move |_| {
                with_bar(id, NativeBar::refresh);
            }),
        );
        self.keep(
            web,
            web.connect_uri_notify(move |_| {
                with_bar(id, NativeBar::refresh);
            }),
        );
        self.keep(
            web,
            web.connect_load_changed(move |_, event| {
                with_bar(id, |bar| bar.load_changed(event));
            }),
        );
        self.keep(web, web.connect_destroy(move |_| teardown(id)));
        if let Some(history) = web.back_forward_list() {
            // `changed` carries a GList the bindings do not wrap; its
            // arguments are not read.
            let handler = history.connect_local("changed", false, move |_| {
                with_bar(id, NativeBar::refresh);
                None
            });
            self.keep(&history, handler);
        }
        self.keep(
            context,
            context.connect_download_started(move |_, download| {
                with_bar(id, |bar| bar.download_announced(download));
            }),
        );
        self.keep(&self.bar, self.bar.connect_destroy(move |_| teardown(id)));
        for (button, action) in self.buttons.iter().zip(ACTIONS) {
            self.keep(
                button,
                button.connect_clicked(move |_| {
                    with_bar(id, |bar| bar.on_click(action));
                }),
            );
        }
    }

    fn load_changed(&self, event: LoadEvent) {
        if matches!(event, LoadEvent::Committed) {
            self.note_main_resource();
        }
        self.refresh();
    }

    /// Record the main resource's response, which a committed load carries
    /// (never logged).
    fn note_main_resource(&self) {
        let Some(response) = self.webview.main_resource().and_then(|r| r.response()) else { return };
        let disposition = response.http_headers().and_then(|h| h.one("Content-Disposition"));
        let recorded = linux_model::main_frame_response(
            response.uri().as_deref(),
            response.mime_type().as_deref(),
            disposition.as_deref(),
        );
        if let Some(recorded) = recorded {
            self.tracker.borrow_mut().record(recorded);
        }
    }

    /// Recompute the state from the webview and render it.
    fn refresh(&self) {
        if self.torn_down.get() {
            return;
        }
        let shown = self.webview.uri().and_then(|u| Url::parse(&u).ok());
        let state = {
            let tracker = self.tracker.borrow();
            transfer::nav_state(
                self.webview.can_go_back(),
                self.webview.can_go_forward(),
                self.webview.is_loading(),
                tracker.for_document(shown.as_ref()),
                self.allow_downloads,
            )
        };
        self.render(&state);
        *self.state.borrow_mut() = state;
    }

    fn render(&self, state: &NavState) {
        let views = linux_model::button_views(state, self.flash.get());
        for (button, view) in self.buttons.iter().zip(views) {
            button.set_sensitive(view.sensitive);
            button.set_tooltip_text(Some(view.tooltip));
            let style = button.style_context();
            if view.alert {
                style.add_class(ALERT_CLASS);
            } else {
                style.remove_class(ALERT_CLASS);
            }
        }
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
        let id = self.id;
        glib::timeout_add_local_once(FLASH_FOR, move || {
            with_bar(id, |bar| bar.end_flash(generation));
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
    /// the operator's action; each is a navigation, so the allow-list, TLS
    /// and HTTP-auth handlers run on it as on a page click.
    fn on_click(&self, action: NavAction) {
        let state = self.state.borrow().clone();
        match action {
            NavAction::Back if state.can_go_back => {
                self.webview.go_back();
                self.audit.nav(NavAction::Back);
            }
            NavAction::Forward if state.can_go_forward => {
                self.webview.go_forward();
                self.audit.nav(NavAction::Forward);
            }
            NavAction::Reload if !state.is_loading => {
                // Binding order (G5): mark before the reload starts, so the
                // fill engine skips the reload's own load.
                mark_operator_reload(&self.shared);
                self.webview.reload();
                self.audit.nav(NavAction::Reload);
            }
            NavAction::Download if state.download_enabled() => self.start_download(),
            _ => {}
        }
    }

    fn refuse(&self, refusal: &'static str) {
        self.audit.download_refused(refusal);
        self.flash(refusal);
    }

    /// The download click. Every refusal before the request is audited and
    /// nothing is fetched.
    fn start_download(&self) {
        let shown = self.webview.uri().and_then(|u| Url::parse(&u).ok());
        let Some(url) = shown else { return self.refuse(reason::UNAVAILABLE) };
        // The same decision the webview's own downloads get (A6), before any
        // byte is requested.
        if let Err(refusal) = transfer::url_policy(self.allow_downloads, &self.origins, &url) {
            return self.refuse(refusal);
        }
        let Some(slot) = self.limiter.try_acquire() else { return self.refuse(reason::TOO_MANY_DOWNLOADS) };
        let Some(dest) = destination() else { return self.refuse(reason::SAVE_IO_ERROR) };
        let id = NEXT_DOWNLOAD.fetch_add(1, Ordering::Relaxed);
        self.downloads.borrow_mut().insert(id, InFlight { transfer: Transfer::new(slot, dest), download: None });

        self.claiming.set(true);
        let download = self.webview.download_uri(url.as_str());
        self.claiming.set(false);
        let announced = std::mem::take(&mut *self.announced.borrow_mut());
        let Some(download) = download else {
            log::warn!("connect.web.nav_bar: WebKitGTK did not start the download");
            return self.fail(id, reason::TRANSFER_FAILED, false);
        };
        if let Err(refusal) = linux_model::claim(announced.contains(&download)) {
            log::warn!(
                "connect.web.nav_bar: WebKitGTK announced the download before the bar could claim it; cancelled"
            );
            download.cancel();
            return self.fail(id, refusal, false);
        }
        let handlers = claim_download(self.id, id, &download);
        CLAIMS.with(|c| c.borrow_mut().insert(id, Claim { download: download.clone(), handlers }));
        if let Some(entry) = self.downloads.borrow_mut().get_mut(&id) {
            entry.download = Some(download);
        }
    }

    /// The context announced a download. Only the claim guard cares: the
    /// webview's own downloads stay with wry and `RemotePolicy::on_download`,
    /// and the bar's claimed ones already have their handlers.
    fn download_announced(&self, download: &webkit2gtk::Download) {
        if self.claiming.get() {
            self.announced.borrow_mut().push(download.clone());
        }
    }

    /// Audit how download `id` ended and close it (`cancel`: stop the
    /// WebKitDownload too).
    fn settle(&self, id: u64, outcome: Settled, cancel: bool) {
        // Out of the map before anything else runs, so a re-entrant signal
        // finds the download settled.
        let entry = self.downloads.borrow_mut().remove(&id);
        match outcome {
            Settled::Saved(saved) => {
                self.audit.download_ok(&saved.filename, &saved.mime, saved.bytes, DownloadPath::Refetch)
            }
            Settled::Refused(refusal) => self.refuse(refusal),
        }
        if let Some(entry) = entry {
            if cancel {
                if let Some(download) = &entry.download {
                    download.cancel();
                }
            }
            // Dropping the transfer cleans up its staging directory and an
            // unfilled placeholder.
            drop(entry.transfer);
        }
    }

    /// Apply `step` to download `id`; if it settles the transfer, audit and
    /// close it. Returns whether the transfer is still open. `step` is pure
    /// Rust (no GTK call), so holding the borrow over it is safe.
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

    /// The response arrived (`decide-destination`); `Some(staging file)` to
    /// save into. The refusal itself stops the download (the handler then
    /// cancels it), so no extra cancel here.
    fn begin(&self, id: u64, download: &webkit2gtk::Download, suggested: &str) -> Option<PathBuf> {
        let facts = match download.response() {
            Some(r) => {
                let disposition = r.http_headers().and_then(|h| h.one("Content-Disposition"));
                linux_model::response_facts(
                    r.uri().as_deref(),
                    r.status_code(),
                    r.mime_type().as_deref(),
                    disposition.as_deref(),
                    r.content_length(),
                    Some(suggested),
                )
            }
            // No response: `check_response` refuses it as unavailable.
            None => ResponseFacts::default(),
        };
        let now = chrono::Local::now().naive_local();
        let mut path = None;
        let open = self.step(id, false, |t| {
            let outcome = t.begin(&facts, self.allow_downloads, &self.origins, now);
            path = t.staging_file().map(Path::to_path_buf);
            outcome
        });
        path.filter(|_| open)
    }

    /// A `received-data`: count WebKitGTK's running total against the cap
    /// (and cancel past it).
    fn on_progress(&self, id: u64, total: u64) {
        self.step(id, true, |t| t.record_total(total));
    }

    fn finish(&self, id: u64) {
        self.step(id, false, Transfer::finish);
    }

    fn fail(&self, id: u64, refusal: &'static str, cancel: bool) {
        self.step(id, cancel, |t| t.fail(refusal));
    }

    // ── Teardown ──

    fn teardown(&self) {
        self.torn_down.set(true);
        for (object, handler) in self.handlers.take() {
            object.disconnect(handler);
        }
        // Not while the box is being destroyed: it is then walking its
        // children (this may be the webview's `destroy`), and removing one
        // under the walk is unsafe in GTK; the box drops the bar itself.
        let parented = self.bar.parent().is_some_and(|p| &p == self.container.upcast_ref::<gtk::Widget>());
        if parented && !self.bar.in_destruction() && !self.container.in_destruction() {
            self.container.remove(&self.bar);
        }
        let ids: Vec<u64> = self.downloads.borrow().keys().copied().collect();
        for id in ids {
            self.fail(id, reason::TRANSFER_FAILED, true);
        }
    }
}

// ── The bar's WebKitDownload ───────────────────────────────────────

/// Connect the bar's handlers on its own download `download`, right after
/// `download_uri` returned it and before WebKitGTK announces it (where wry
/// connects `RemotePolicy::on_download`). Each closure holds ids only, and
/// none depends on the bar still being attached: the download stays the
/// bar's until it finishes.
fn claim_download(bar_id: u64, download_id: u64, download: &webkit2gtk::Download) -> Vec<SignalHandlerId> {
    let decide = download.connect_decide_destination(move |download, suggested| {
        let staging = with_bar(bar_id, |bar| bar.begin(download_id, download, suggested)).flatten();
        match staging.as_deref().and_then(linux_model::destination_uri) {
            Some(uri) => download.set_destination(&uri),
            // Refused (already audited), or the bar is gone.
            None => download.cancel(),
        }
        // Handled, always: `decide-destination` stops at the first handler
        // that returns TRUE, so wry's (connected later) never decides it.
        true
    });
    let data = download.connect_received_data(move |download, _chunk| {
        let total = download.received_data_length();
        if with_bar(bar_id, |bar| bar.on_progress(download_id, total)).is_none() {
            download.cancel();
        }
    });
    // The error is not logged: its message can carry the URL.
    let failed = download.connect_failed(move |download, _error| {
        // Keep wry's handler (and so `RemotePolicy::on_download`) off it.
        download.stop_signal_emission_by_name("failed");
        with_bar(bar_id, |bar| bar.fail(download_id, reason::TRANSFER_FAILED, false));
    });
    let finished = download.connect_finished(move |download| {
        download.stop_signal_emission_by_name("finished");
        with_bar(bar_id, |bar| bar.finish(download_id));
        release_claim(download_id);
    });
    vec![decide, data, failed, finished]
}

/// Disconnect a finished download's handlers, on a later turn of the main
/// loop (`finished` is still being emitted when this is called).
fn release_claim(download_id: u64) {
    glib::idle_add_local_once(move || {
        if let Some(claim) = CLAIMS.with(|c| c.borrow_mut().remove(&download_id)) {
            for handler in claim.handlers {
                claim.download.disconnect(handler);
            }
        }
    });
}
