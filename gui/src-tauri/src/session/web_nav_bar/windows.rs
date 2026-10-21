//! Windows shim for the web session nav bar: a native Win32 strip with back,
//! forward, reload and download at the bottom of the session window
//! (docs/specs/2026-10-20-web-session-nav-controls-design.md §6, §7, §8).
//!
//! **Layout.** wry 0.55 hosts the WebView2 controller in a `WRY_WEBVIEW`
//! container window, a child of the session window. In the default build
//! (`WebviewKind::WindowContent`) wry subclasses the session window and, on
//! every `WM_SIZE` that is not a minimise, sizes the controller and the
//! container to the whole client area. The bar is a child window of the
//! session window, a sibling of that container, and the shim subclasses the
//! session window too: its procedure lets the rest of the chain (wry's
//! included) handle `WM_SIZE` / `WM_DPICHANGED` first, then gives the
//! container and the controller the client area minus the bar's strip and
//! puts the bar in that strip ([`windows_model::layout`]). Same message, same
//! thread, so the last word is the bar's and nothing is painted in between;
//! a DPI change, a maximise and a restore all arrive as `WM_SIZE` and are
//! recomputed from the client area and `GetDpiForWindow`. With
//! [`WebviewFrame::HostManaged`] (the `web_session_chrome` window, whose own
//! resize handler places the remote webview) only the bar is placed, and the
//! host must leave [`super::BAR_HEIGHT`] free. The buttons are standard
//! `BUTTON` controls with Segoe MDL2 glyphs; a click moves keyboard focus
//! back into the page.
//!
//! **State.** Back and forward follow `HistoryChanged` (`CanGoBack` /
//! `CanGoForward`), reload follows `NavigationStarting` /
//! `NavigationCompleted`, and the shown URL follows `SourceChanged`. The
//! download button needs the shown main-frame response's `Content-Type` and
//! `Content-Disposition`: `WebResourceResponseReceived` reports every
//! response, and the one whose request URI is the latest top-level
//! navigation's (or one of its redirects') is recorded in the shared
//! `transfer::ResponseTracker` ([`windows_model::MainFrameNav`]). Every
//! handler is an extra registration next to wry's; none of wry's is
//! replaced or removed, and none of the bar's changes an event's outcome.
//!
//! **Download.** WebView2 cannot save the document it shows, so the bar
//! fetches it again itself (`windows_refetch`, `path=refetch`): never a
//! bypass of `RemotePolicy::on_download` (A6), the click runs the same
//! `web::download_decision` on the shown URL before anything is requested
//! (`transfer::url_policy`), then [`windows_model::refetch_gate`] refuses
//! (`refetch_blocked`) any session whose webview loads are trusted or routed
//! in a way the request could not reproduce: a TLS profile with pins, a
//! certificate the operator accepted for the origin, no TLS gate to tell, or
//! proxy mode; and [`windows_model::system_proxy_gate`] refuses it when the
//! user's system proxy settings, which WebView2 follows, name a proxy, a PAC
//! script or auto-detection (or cannot be read). Only then are the
//! webview's cookies for the URL read (`ICoreWebView2CookieManager::GetCookies`;
//! `Secure` ones dropped again on plain http) and the request started on the
//! async runtime. Downloads the webview escalates itself
//! (`DownloadStarting`) are not the bar's: they stay on wry's handler and
//! `RemotePolicy::on_download`, as before this change. The complete staging
//! file gets a `Zone.Identifier` stream (zone 3) before it is moved into
//! Downloads, which the request does not get from WebView2.
//!
//! **Isolation.** Nothing here gives the page a way in: no script is
//! injected or run, no host object is exposed and no page-to-host message
//! channel exists (spec §8.1; `windows_model::tests::test_bar_is_not_a_dom_node`).
//! The page cannot reach a Win32 window of the host.
//!
//! **Threads and lifetimes.** Win32 windows and WebView2 objects belong to
//! the UI thread, and so does everything here: `install` runs in the
//! `with_webview` closure, WebView2 raises its events there, the window
//! procedures run there, and the `Send` [`NavBar`] handle and the end of a
//! download reach it through `AppHandle::run_on_main_thread`. Native state
//! lives in the [`BARS`] registry; every callback captures integer ids
//! only, so a callback after teardown finds nothing. Teardown runs on
//! [`NavBar::detach`] or on the session window's `WM_DESTROY`, whichever is
//! first: it removes the subclass and every event registration, destroys
//! the bar's windows, gives the webview its whole client area back (detach
//! only) and ends in-flight downloads, each with one audit line.
//!
//! **Every `unsafe` block** is a Win32 or COM call on objects owned by the
//! UI thread it runs on; each carries its invariant.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use ::windows::core::{s, w, Interface, BOOL, HSTRING, PCWSTR, PWSTR};
use ::windows::Win32::Foundation::{
    GetLastError, GlobalFree, COLORREF, ERROR_CLASS_ALREADY_EXISTS, HGLOBAL, HINSTANCE, HWND, LPARAM, LRESULT, RECT,
    WPARAM,
};
use ::windows::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, GetSysColorBrush, InvalidateRect, SetBkMode, SetTextColor, CLEARTYPE_QUALITY,
    CLIP_DEFAULT_PRECIS, COLOR_BTNFACE, DEFAULT_CHARSET, DEFAULT_PITCH, FF_DONTCARE, FW_NORMAL, HDC, HFONT, HGDIOBJ,
    OUT_DEFAULT_PRECIS, TRANSPARENT,
};
use ::windows::Win32::Networking::WinHttp::{
    WinHttpGetIEProxyConfigForCurrentUser, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG,
};
use ::windows::Win32::System::Com::CoTaskMemFree;
use ::windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use ::windows::Win32::System::SystemServices::{SS_CENTERIMAGE, SS_ENDELLIPSIS, SS_LEFT, SS_NOPREFIX};
use ::windows::Win32::UI::Controls::{
    TOOLTIPS_CLASSW, TOOLTIP_FLAGS, TTF_IDISHWND, TTF_SUBCLASS, TTM_ADDTOOLW, TTM_NEWTOOLRECTW, TTM_UPDATETIPTEXTW,
    TTS_ALWAYSTIP, TTS_NOPREFIX, TTTOOLINFOW,
};
use ::windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use ::windows::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use ::windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetClientRect, GetParent, KillTimer, LoadCursorW, RegisterClassExW,
    SendMessageW, SetTimer, SetWindowPos, SetWindowTextW, BN_CLICKED, BS_PUSHBUTTON, CS_HREDRAW, CS_VREDRAW,
    CW_USEDEFAULT, HMENU, HWND_TOP, IDC_ARROW, SIZE_MINIMIZED, SWP_NOACTIVATE, SWP_NOZORDER, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_COMMAND, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED, WM_SETFONT, WM_SIZE, WM_TIMER, WNDCLASSEXW,
    WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_DISABLED, WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};
use tauri::{AppHandle, Url};
use tokio::sync::watch;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2Controller, ICoreWebView2CookieList, ICoreWebView2CookieManager,
    ICoreWebView2HttpResponseHeaders, ICoreWebView2Settings2, ICoreWebView2WebResourceResponseReceivedEventArgs,
    ICoreWebView2_2, COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC,
};
use webview2_com::{
    take_pwstr, GetCookiesCompletedHandler, HistoryChangedEventHandler, NavigationCompletedEventHandler,
    NavigationStartingEventHandler, SourceChangedEventHandler, WebResourceResponseReceivedEventHandler,
};
use zeroize::Zeroizing;

use super::linux_model::{self, ACTIONS};
use super::transfer::{self, ResponseTracker, Settled, Transfer};
use super::windows_model::{self, Rect, SessionTls};
use super::windows_refetch::{self, Policy, Refetch};
use super::{
    mark_operator_reload, reason, DownloadLimiter, DownloadPath, NavAction, NavBar, NavBarAudit, NavBarConfig,
    NavState, WebviewFrame,
};
use crate::session::web::{OriginSet, WebOrigin, WebShared};
use crate::session::web_tls_pin::TlsPinGate;

// ── Public surface ─────────────────────────────────────────────────

/// Attach the bar to the session's remote webview. Same contract as
/// `macos::attach` and `linux::attach`: call it right after the webview is
/// built (`build_window`), from any thread. The native work is queued to the
/// UI thread through `with_webview`, ahead of the native handlers' install
/// and of the navigation to the start URL. The returned handle is inert until
/// then, and if the webview is already gone. A bar that cannot be attached
/// leaves the window without one (logged); it is never a policy gate, so
/// nothing else depends on it.
pub fn attach(remote: &tauri::Webview, config: NavBarConfig) -> Box<dyn NavBar> {
    let id = NEXT_BAR.fetch_add(1, Ordering::Relaxed);
    let handle = WinNavBar { id, app: config.audit.app.clone() };
    let context = format!("resource={} token={}", config.audit.resource, config.audit.token);
    let queued = remote.with_webview(move |webview| {
        if let Err(why) = install(id, &webview, config) {
            log::warn!("connect.web.nav_bar: not attached: {context} — {why}");
        }
    });
    if let Err(e) = queued {
        log::warn!("connect.web.nav_bar: not attached, the session webview is gone: {e}");
    }
    Box::new(handle)
}

/// The `Send` handle: an id into the UI thread's registry.
struct WinNavBar {
    id: u64,
    app: AppHandle,
}

impl WinNavBar {
    /// Run `f` on the UI thread (at once when already there).
    fn on_main(&self, f: impl FnOnce() + Send + 'static) {
        if let Err(e) = self.app.run_on_main_thread(f) {
            log::warn!("connect.web.nav_bar: could not reach the main thread: {e}");
        }
    }
}

impl NavBar for WinNavBar {
    /// Render `state` until the next change the shim observes itself (a
    /// WebView2 event), which recomputes it from the webview.
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
        self.on_main(move || teardown(id, false));
    }
}

// ── Registry ───────────────────────────────────────────────────────

static NEXT_BAR: AtomicU64 = AtomicU64::new(1);
static NEXT_DOWNLOAD: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// UI thread only: every live bar, by id.
    static BARS: RefCell<HashMap<u64, Rc<NativeBar>>> = RefCell::new(HashMap::new());
    /// UI thread only: whether the bar's window class is registered.
    static CLASS_REGISTERED: Cell<bool> = const { Cell::new(false) };
}

fn bar(id: u64) -> Option<Rc<NativeBar>> {
    BARS.with(|b| b.borrow().get(&id).cloned())
}

/// Run `f` on bar `id` if it is still attached. The registry borrow is
/// released before `f` runs, so `f` may tear the bar down.
fn with_bar<R>(id: u64, f: impl FnOnce(&NativeBar) -> R) -> Option<R> {
    bar(id).map(|b| f(&b))
}

/// The bar whose own window is `hwnd`.
fn bar_of_window(hwnd: HWND) -> Option<Rc<NativeBar>> {
    BARS.with(|b| b.borrow().values().find(|n| n.windows.bar == hwnd).cloned())
}

/// `window_gone`: the session window is being destroyed, so the webview is
/// not laid out again.
fn teardown(id: u64, window_gone: bool) {
    let Some(native) = BARS.with(|b| b.borrow_mut().remove(&id)) else { return };
    native.teardown(window_gone);
}

// ── Win32 helpers ──────────────────────────────────────────────────

/// The bar's window class.
const BAR_CLASS: PCWSTR = w!("BastionVaultWebNavBar");

/// The download button's short-lived error state.
const FLASH_TIMER: usize = 1;

/// The status text's colour while a refusal flashes (`RGB(0xC4, 0x2B, 0x1C)`,
/// `COLORREF` is `0x00BBGGRR`).
const ALERT_TEXT: COLORREF = COLORREF(0x001C_2BC4);

/// `TTTOOLINFOW` up to `lParam` (`TTTOOLINFOW_V2_SIZE`), which every
/// comctl32 that ships with Windows 10 accepts.
const TOOL_INFO_SIZE: u32 = std::mem::offset_of!(TTTOOLINFOW, lpReserved) as u32;

/// A NUL-terminated UTF-16 copy of `s`.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

type GetDpiForWindowFn = unsafe extern "system" fn(HWND) -> u32;

/// The window's DPI. `GetDpiForWindow` exists from Windows 10 1607 on and is
/// looked up at run time (as wry and tao do), so an older release starts
/// and gets a 96-DPI bar rather than failing to load the executable.
fn dpi_of(window: HWND) -> u32 {
    static GET_DPI_FOR_WINDOW: OnceLock<Option<GetDpiForWindowFn>> = OnceLock::new();
    let lookup = GET_DPI_FOR_WINDOW.get_or_init(|| {
        // SAFETY: `user32.dll` is loaded in every process with a window, and
        // both names are NUL-terminated literals.
        let proc = unsafe {
            let user32 = GetModuleHandleW(w!("user32.dll")).ok()?;
            GetProcAddress(user32, s!("GetDpiForWindow"))?
        };
        // SAFETY: the export's documented signature (WinUser.h) is
        // `UINT WINAPI GetDpiForWindow(HWND)`; both are `extern "system"`
        // function pointers of the same size.
        Some(unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, GetDpiForWindowFn>(proc) })
    });
    match lookup {
        // SAFETY: `window` is the session window, alive while the bar is.
        Some(get) => match unsafe { get(window) } {
            0 => windows_model::BASE_DPI,
            dpi => dpi,
        },
        None => windows_model::BASE_DPI,
    }
}

/// A font of `size_dip` at `dpi`.
fn font(face: &str, size_dip: i32, dpi: u32) -> HFONT {
    let face = wide(face);
    // SAFETY: `face` is NUL-terminated and outlives the call; the font is
    // deleted by `Fonts::drop` once no window uses it.
    unsafe {
        CreateFontW(
            -windows_model::scale(size_dip, dpi),
            0,
            0,
            0,
            FW_NORMAL.0 as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            u32::from(DEFAULT_PITCH.0 | FF_DONTCARE.0),
            PCWSTR(face.as_ptr()),
        )
    }
}

/// The bar's two fonts at one DPI.
struct Fonts {
    icon: HFONT,
    text: HFONT,
}

impl Drop for Fonts {
    fn drop(&mut self) {
        // SAFETY: fonts this bar created, deleted once; the windows that used
        // them have been given new ones or destroyed.
        unsafe {
            let _ = DeleteObject(HGDIOBJ::from(self.icon));
            let _ = DeleteObject(HGDIOBJ::from(self.text));
        }
    }
}

/// Copy a CoTaskMem string WebView2 returned into a zeroizing buffer, then
/// wipe and free the original.
///
/// # Safety
/// `value` is null or a NUL-terminated string WebView2 allocated with
/// `CoTaskMemAlloc` and handed to the caller, who owns it.
unsafe fn take_secret(value: PWSTR) -> Zeroizing<String> {
    if value.is_null() {
        return Zeroizing::new(String::new());
    }
    // SAFETY: the caller's contract; `as_wide` stops at the terminator.
    let (copy, len) = unsafe {
        let units = value.as_wide();
        (windows_model::utf16_secret(units), units.len())
    };
    // SAFETY: overwrites the `len` code units just read, in a buffer the
    // caller owns, then frees it, once.
    unsafe {
        std::ptr::write_bytes(value.0, 0, len);
        CoTaskMemFree(Some(value.0 as *const c_void));
    }
    copy
}

/// One response header, when present.
fn header(headers: &ICoreWebView2HttpResponseHeaders, name: PCWSTR) -> Option<String> {
    let mut present = BOOL::default();
    let mut value = PWSTR::null();
    // SAFETY: COM reads on the headers WebView2 handed the event handler, on
    // the UI thread; the out-pointers are locals and `take_pwstr` frees the
    // string.
    unsafe {
        headers.Contains(name, &mut present).ok()?;
        if !present.as_bool() {
            return None;
        }
        headers.GetHeader(name, &mut value).ok()?;
    }
    Some(take_pwstr(value))
}

/// The bar's windows, children of the session window.
#[derive(Clone, Copy)]
struct BarWindows {
    bar: HWND,
    buttons: [HWND; 4],
    label: HWND,
    tooltip: HWND,
}

fn module_instance() -> Result<HINSTANCE, &'static str> {
    // SAFETY: the handle of the executable itself, which outlives the bar.
    let module = unsafe { GetModuleHandleW(PCWSTR::null()) }.map_err(|_| "no module handle")?;
    Ok(module.into())
}

fn register_bar_class(instance: HINSTANCE) -> Result<(), &'static str> {
    if CLASS_REGISTERED.with(Cell::get) {
        return Ok(());
    }
    // SAFETY: registering a class whose procedure is `bar_proc` and whose
    // name and brush are static; the cursor is a shared system one.
    let registered = unsafe {
        let class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(bar_proc),
            hInstance: instance,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
            lpszClassName: BAR_CLASS,
            ..Default::default()
        };
        RegisterClassExW(&class) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS
    };
    if !registered {
        return Err("could not register the bar's window class");
    }
    CLASS_REGISTERED.with(|c| c.set(true));
    Ok(())
}

/// Create the bar, its four buttons, its status text and its tooltip
/// control, all hidden from the page's reach (they are host windows).
fn create_windows(window: HWND, instance: HINSTANCE) -> Result<BarWindows, &'static str> {
    // SAFETY: creating child windows of the session window on the thread
    // that owns it; every string argument is NUL-terminated and outlives its
    // call; a partly built bar is destroyed before returning an error.
    unsafe {
        let bar = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            BAR_CLASS,
            PCWSTR::null(),
            WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
            0,
            0,
            0,
            0,
            Some(window),
            None,
            Some(instance),
            None,
        )
        .map_err(|_| "could not create the bar window")?;
        let fail = |why| {
            let _ = DestroyWindow(bar);
            why
        };
        let mut buttons = [HWND::default(); 4];
        for (slot, action) in buttons.iter_mut().zip(ACTIONS) {
            let glyph = wide(&windows_model::button_glyph(action).to_string());
            *slot = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("BUTTON"),
                PCWSTR(glyph.as_ptr()),
                WS_CHILD | WS_VISIBLE | WS_DISABLED | WINDOW_STYLE(BS_PUSHBUTTON as u32),
                0,
                0,
                0,
                0,
                Some(bar),
                Some(HMENU(usize::from(windows_model::command_id(action)) as *mut c_void)),
                Some(instance),
                None,
            )
            .map_err(|_| fail("could not create a bar button"))?;
        }
        let label = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("STATIC"),
            PCWSTR::null(),
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(SS_LEFT.0 | SS_CENTERIMAGE.0 | SS_NOPREFIX.0 | SS_ENDELLIPSIS.0),
            0,
            0,
            0,
            0,
            Some(bar),
            None,
            Some(instance),
            None,
        )
        .map_err(|_| fail("could not create the bar's status text"))?;
        // Owned by the bar, so it goes with it.
        let tooltip = CreateWindowExW(
            WS_EX_TOPMOST,
            TOOLTIPS_CLASSW,
            PCWSTR::null(),
            WS_POPUP | WINDOW_STYLE(TTS_ALWAYSTIP | TTS_NOPREFIX),
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            Some(bar),
            None,
            Some(instance),
            None,
        )
        .map_err(|_| fail("could not create the bar's tooltip"))?;
        Ok(BarWindows { bar, buttons, label, tooltip })
    }
}

/// The two tools of button `index`: the button itself (shown while it is
/// enabled), and its rectangle on the bar (shown while it is disabled: a
/// disabled window gets no mouse input, its parent does). Their ids.
fn tools(windows: &BarWindows, index: usize) -> [(HWND, usize, TOOLTIP_FLAGS); 2] {
    let button = windows.buttons[index];
    [(button, button.0 as usize, TTF_IDISHWND), (windows.bar, index + 1, TOOLTIP_FLAGS(0))]
}

fn rect(r: &Rect) -> RECT {
    RECT { left: r.x, top: r.y, right: r.x + r.width, bottom: r.y + r.height }
}

// ── The bar ────────────────────────────────────────────────────────

struct NativeBar {
    id: u64,
    app: AppHandle,
    audit: Arc<NavBarAudit>,
    allow_downloads: bool,
    origins: Arc<OriginSet>,
    shared: Arc<WebShared>,
    tls_pin: Option<Arc<TlsPinGate>>,
    proxy_mode: bool,
    frame: WebviewFrame,
    limiter: Arc<DownloadLimiter>,
    controller: ICoreWebView2Controller,
    core: ICoreWebView2,
    /// `ICoreWebView2_2` (WebView2 runtime 86+): responses and cookies.
    core2: Option<ICoreWebView2_2>,
    /// The session window.
    window: HWND,
    /// wry's container window, the controller's parent.
    container: HWND,
    windows: BarWindows,
    fonts: RefCell<Option<Fonts>>,
    dpi: Cell<u32>,
    tokens: Cell<Tokens>,
    nav: RefCell<windows_model::MainFrameNav>,
    tracker: RefCell<ResponseTracker>,
    state: RefCell<NavState>,
    flash: Cell<Option<&'static str>>,
    downloads: RefCell<HashMap<u64, InFlight>>,
    torn_down: Cell<bool>,
}

/// The WebView2 event registrations, removed at teardown.
#[derive(Debug, Clone, Copy, Default)]
struct Tokens {
    history: Option<i64>,
    source: Option<i64>,
    starting: Option<i64>,
    completed: Option<i64>,
    response: Option<i64>,
}

/// One of the bar's downloads that has not settled yet.
enum InFlight {
    /// Waiting for the webview's cookies.
    Cookies(Box<Waiting>),
    /// The request runs on the async runtime. Sending `true`, or dropping
    /// the sender, ends it; it audits its own end.
    Running { cancel: watch::Sender<bool> },
}

/// A download waiting for the webview's cookies.
struct Waiting {
    transfer: Transfer,
    url: Url,
}

fn destination() -> Option<transfer::Destination> {
    // `%LOCALAPPDATA%\.bastion_vault_gui`, the crate's per-user data folder.
    let app_root = crate::embedded::app_root().ok();
    windows_model::destination(dirs::download_dir(), dirs::home_dir(), app_root, std::env::temp_dir())
}

/// The current user's WinINET proxy settings, which WebView2 follows; `None`
/// when they cannot be read (the caller then refuses, fail closed). Only
/// whether each kind is set is kept, never the proxy names or the PAC URL.
fn system_proxy() -> Option<windows_model::SystemProxy> {
    let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
    // SAFETY: fills a local struct; on success its strings are WinHTTP's
    // `GlobalAlloc` copies, read and freed below, each once.
    unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut config) }.ok()?;
    let set = |s: PWSTR| {
        // SAFETY: a NUL-terminated string WinHTTP returned, or null.
        !s.is_null() && unsafe { *s.0 } != 0
    };
    let proxy = windows_model::SystemProxy {
        static_proxy: set(config.lpszProxy),
        pac_url: set(config.lpszAutoConfigUrl),
        auto_detect: config.fAutoDetect.as_bool(),
    };
    for s in [config.lpszAutoConfigUrl, config.lpszProxy, config.lpszProxyBypass] {
        if !s.is_null() {
            // SAFETY: frees a string the call above allocated for us, once.
            let _ = unsafe { GlobalFree(Some(HGLOBAL(s.0.cast()))) };
        }
    }
    Some(proxy)
}

/// Build the bar on the UI thread (the `with_webview` closure).
fn install(id: u64, webview: &tauri::webview::PlatformWebview, config: NavBarConfig) -> Result<(), &'static str> {
    let controller = webview.controller();
    let mut container = HWND::default();
    // SAFETY: COM and Win32 reads on the objects tauri hands the
    // `with_webview` closure, on the UI thread that owns them; the
    // out-pointer is a local.
    let (core, window) = unsafe {
        let core = controller.CoreWebView2().map_err(|_| "the webview has no CoreWebView2")?;
        controller.ParentWindow(&mut container).map_err(|_| "the webview has no host window")?;
        (core, GetParent(container).map_err(|_| "the webview's host window has no parent")?)
    };
    let core2 = core.cast::<ICoreWebView2_2>().ok();
    if core2.is_none() {
        log::warn!("connect.web.nav_bar: this WebView2 runtime has no ICoreWebView2_2; the download button stays off");
    }
    let instance = module_instance()?;
    register_bar_class(instance)?;
    let windows = create_windows(window, instance)?;
    let native = Rc::new(NativeBar {
        id,
        app: config.audit.app.clone(),
        audit: Arc::new(config.audit),
        allow_downloads: config.allow_downloads,
        origins: config.origins,
        shared: config.shared,
        tls_pin: config.tls_pin,
        proxy_mode: config.proxy_mode,
        frame: config.frame,
        limiter: Arc::new(DownloadLimiter::new()),
        controller,
        core,
        core2,
        window,
        container,
        windows,
        fonts: RefCell::new(None),
        dpi: Cell::new(0),
        tokens: Cell::new(Tokens::default()),
        nav: RefCell::new(windows_model::MainFrameNav::default()),
        tracker: RefCell::new(ResponseTracker::default()),
        state: RefCell::new(NavState { allow_downloads: config.allow_downloads, ..NavState::default() }),
        flash: Cell::new(None),
        downloads: RefCell::new(HashMap::new()),
        torn_down: Cell::new(false),
    });
    BARS.with(|b| b.borrow_mut().insert(id, Rc::clone(&native)));
    if let Err(why) = native.hook() {
        teardown(id, false);
        return Err(why);
    }
    native.add_tools();
    native.layout();
    // The start URL's navigation may have begun before the handlers existed.
    let shown = native.shown_url();
    native.nav.borrow_mut().seed(shown);
    native.refresh();
    Ok(())
}

impl NativeBar {
    fn subclass_id(&self) -> usize {
        self.id as usize
    }

    /// Subclass the session window and register the WebView2 handlers.
    fn hook(&self) -> Result<(), &'static str> {
        // SAFETY: subclassing the session window on its own thread; the
        // procedure finds the bar by id and the subclass is removed at
        // teardown, on `WM_DESTROY` at the latest.
        let subclassed =
            unsafe { SetWindowSubclass(self.window, Some(parent_proc), self.subclass_id(), self.id as usize) };
        if !subclassed.as_bool() {
            return Err("could not subclass the session window");
        }
        let id = self.id;
        let mut tokens = Tokens::default();
        let result = self.register(id, &mut tokens);
        // Whatever was registered is removed at teardown, even on an error.
        self.tokens.set(tokens);
        result
    }

    fn register(&self, id: u64, tokens: &mut Tokens) -> Result<(), &'static str> {
        let history = HistoryChangedEventHandler::create(Box::new(move |_, _| {
            with_bar(id, NativeBar::refresh);
            Ok(())
        }));
        let source = SourceChangedEventHandler::create(Box::new(move |_, _| {
            with_bar(id, NativeBar::refresh);
            Ok(())
        }));
        let starting = NavigationStartingEventHandler::create(Box::new(move |_, args| {
            let Some(args) = args else { return Ok(()) };
            let mut navigation = 0u64;
            let mut uri = PWSTR::null();
            let mut cancelled = BOOL::default();
            // SAFETY: COM reads on the event arguments WebView2 passed this
            // handler, on the UI thread; the out-pointers are locals and
            // `take_pwstr` frees the string. A read error leaves the default.
            let uri = unsafe {
                let _ = args.NavigationId(&mut navigation);
                let _ = args.Cancel(&mut cancelled);
                let _ = args.Uri(&mut uri);
                take_pwstr(uri)
            };
            with_bar(id, |bar| bar.navigation_started(navigation, &uri, cancelled.as_bool()));
            Ok(())
        }));
        let completed = NavigationCompletedEventHandler::create(Box::new(move |_, args| {
            let Some(args) = args else { return Ok(()) };
            let mut navigation = 0u64;
            // SAFETY: a COM read on the event arguments, on the UI thread.
            if unsafe { args.NavigationId(&mut navigation) }.is_ok() {
                with_bar(id, |bar| bar.navigation_completed(navigation));
            }
            Ok(())
        }));
        // SAFETY: registering handlers on the webview this bar is attached
        // to, on its UI thread; every token is removed at teardown.
        unsafe {
            let mut token = 0i64;
            self.core.add_HistoryChanged(&history, &mut token).map_err(|_| "add_HistoryChanged")?;
            tokens.history = Some(token);
            self.core.add_SourceChanged(&source, &mut token).map_err(|_| "add_SourceChanged")?;
            tokens.source = Some(token);
            self.core.add_NavigationStarting(&starting, &mut token).map_err(|_| "add_NavigationStarting")?;
            tokens.starting = Some(token);
            self.core.add_NavigationCompleted(&completed, &mut token).map_err(|_| "add_NavigationCompleted")?;
            tokens.completed = Some(token);
            if let Some(core2) = &self.core2 {
                let response = WebResourceResponseReceivedEventHandler::create(Box::new(move |_, args| {
                    if let Some(args) = args {
                        with_bar(id, |bar| bar.response_received(&args));
                    }
                    Ok(())
                }));
                core2
                    .add_WebResourceResponseReceived(&response, &mut token)
                    .map_err(|_| "add_WebResourceResponseReceived")?;
                tokens.response = Some(token);
            }
        }
        Ok(())
    }

    /// Two tooltip tools per button ([`tools`]); their texts are set by
    /// [`Self::render`] and the rectangles by [`Self::layout`].
    fn add_tools(&self) {
        let mut empty = wide("");
        for index in 0..ACTIONS.len() {
            for (owner, tool, flags) in tools(&self.windows, index) {
                let mut info = TTTOOLINFOW {
                    cbSize: TOOL_INFO_SIZE,
                    uFlags: flags | TTF_SUBCLASS,
                    hwnd: owner,
                    uId: tool,
                    lpszText: PWSTR(empty.as_mut_ptr()),
                    ..Default::default()
                };
                // SAFETY: a message to the bar's own tooltip control, on its
                // thread; `info` and the text it points at outlive the call
                // (the control copies them).
                unsafe {
                    SendMessageW(
                        self.windows.tooltip,
                        TTM_ADDTOOLW,
                        Some(WPARAM(0)),
                        Some(LPARAM(&mut info as *mut TTTOOLINFOW as isize)),
                    )
                };
            }
        }
    }

    /// Give the webview the client area above the bar and the bar the strip
    /// below it, at the window's current DPI.
    fn layout(&self) {
        if self.torn_down.get() {
            return;
        }
        let mut client = RECT::default();
        // SAFETY: reads the session window's client rectangle, on its thread.
        if unsafe { GetClientRect(self.window, &mut client) }.is_err() {
            return;
        }
        let dpi = dpi_of(self.window);
        if dpi != self.dpi.get() {
            self.apply_fonts(dpi);
        }
        let l = windows_model::layout(client.right - client.left, client.bottom - client.top, dpi);
        let w = &self.windows;
        // SAFETY: moving the bar's own windows and wry's container, children
        // of the session window, on the thread that owns them; the
        // controller is the one this bar is attached to.
        unsafe {
            if self.frame == WebviewFrame::ShrinkToFit {
                let v = l.webview;
                let _ = SetWindowPos(self.container, None, v.x, v.y, v.width, v.height, SWP_NOZORDER | SWP_NOACTIVATE);
                let _ = self.controller.SetBounds(RECT { left: 0, top: 0, right: v.width, bottom: v.height });
            }
            let b = l.bar;
            let _ = SetWindowPos(w.bar, Some(HWND_TOP), b.x, b.y, b.width, b.height, SWP_NOACTIVATE);
            for (index, (button, r)) in w.buttons.iter().zip(l.buttons.iter()).enumerate() {
                let _ = SetWindowPos(*button, None, r.x, r.y, r.width, r.height, SWP_NOZORDER | SWP_NOACTIVATE);
                let mut info = TTTOOLINFOW {
                    cbSize: TOOL_INFO_SIZE,
                    hwnd: w.bar,
                    uId: index + 1,
                    rect: rect(r),
                    ..Default::default()
                };
                SendMessageW(
                    w.tooltip,
                    TTM_NEWTOOLRECTW,
                    Some(WPARAM(0)),
                    Some(LPARAM(&mut info as *mut TTTOOLINFOW as isize)),
                );
            }
            let t = l.label;
            let _ = SetWindowPos(w.label, None, t.x, t.y, t.width, t.height, SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }

    /// New fonts for `dpi`; the old ones are deleted once replaced.
    fn apply_fonts(&self, dpi: u32) {
        let fonts = Fonts {
            icon: font(windows_model::ICON_FONT, windows_model::ICON_SIZE_DIP, dpi),
            text: font(windows_model::TEXT_FONT, windows_model::TEXT_SIZE_DIP, dpi),
        };
        // SAFETY: `WM_SETFONT` to the bar's own controls, on their thread;
        // the fonts stay alive in `self.fonts` while the controls use them.
        unsafe {
            for button in self.windows.buttons {
                SendMessageW(button, WM_SETFONT, Some(WPARAM(fonts.icon.0 as usize)), Some(LPARAM(1)));
            }
            SendMessageW(self.windows.label, WM_SETFONT, Some(WPARAM(fonts.text.0 as usize)), Some(LPARAM(1)));
        }
        self.dpi.set(dpi);
        // The previous fonts, if any, are dropped (deleted) here.
        *self.fonts.borrow_mut() = Some(fonts);
    }

    fn shown_url(&self) -> Option<Url> {
        let mut source = PWSTR::null();
        // SAFETY: a COM read on the webview, on the UI thread; `take_pwstr`
        // frees the string.
        unsafe { self.core.Source(&mut source) }.ok()?;
        Url::parse(&take_pwstr(source)).ok()
    }

    fn history(&self) -> (bool, bool) {
        let (mut back, mut forward) = (BOOL::default(), BOOL::default());
        // SAFETY: COM reads on the webview, on the UI thread; a failed read
        // leaves `false`.
        unsafe {
            let _ = self.core.CanGoBack(&mut back);
            let _ = self.core.CanGoForward(&mut forward);
        }
        (back.as_bool(), forward.as_bool())
    }

    /// Recompute the state from the webview and render it.
    fn refresh(&self) {
        if self.torn_down.get() {
            return;
        }
        let shown = self.shown_url();
        let (back, forward) = self.history();
        let loading = self.nav.borrow().is_loading();
        let state = {
            let tracker = self.tracker.borrow();
            transfer::nav_state(back, forward, loading, tracker.for_document(shown.as_ref()), self.allow_downloads)
        };
        self.render(&state);
        *self.state.borrow_mut() = state;
    }

    fn render(&self, state: &NavState) {
        if self.torn_down.get() {
            return;
        }
        let views = linux_model::button_views(state, self.flash.get());
        for (index, view) in views.iter().enumerate() {
            let mut text = wide(view.tooltip);
            // SAFETY: messages to the bar's own windows, on their thread;
            // `info` and `text` outlive each call (the control copies them).
            unsafe {
                let _ = EnableWindow(self.windows.buttons[index], view.sensitive);
                for (owner, tool, _) in tools(&self.windows, index) {
                    let mut info = TTTOOLINFOW {
                        cbSize: TOOL_INFO_SIZE,
                        hwnd: owner,
                        uId: tool,
                        lpszText: PWSTR(text.as_mut_ptr()),
                        ..Default::default()
                    };
                    SendMessageW(
                        self.windows.tooltip,
                        TTM_UPDATETIPTEXTW,
                        Some(WPARAM(0)),
                        Some(LPARAM(&mut info as *mut TTTOOLINFOW as isize)),
                    );
                }
            }
        }
        let status = wide(windows_model::status_text(self.flash.get()));
        // SAFETY: the bar's own status text, on its thread; `status` is
        // NUL-terminated and outlives the call.
        unsafe {
            let _ = SetWindowTextW(self.windows.label, PCWSTR(status.as_ptr()));
            let _ = InvalidateRect(Some(self.windows.label), None, true);
        }
    }

    /// Show `refusal` on the bar for a few seconds (the short-lived error
    /// state, spec §7.6).
    fn flash(&self, refusal: &'static str) {
        if self.torn_down.get() {
            return;
        }
        self.flash.set(Some(refusal));
        let state = self.state.borrow().clone();
        self.render(&state);
        // SAFETY: a timer on the bar's own window, on its thread; arming the
        // same id again restarts it, and it dies with the window.
        unsafe { SetTimer(Some(self.windows.bar), FLASH_TIMER, windows_model::FLASH_FOR_MS, None) };
    }

    fn end_flash(&self) {
        self.flash.set(None);
        let state = self.state.borrow().clone();
        self.render(&state);
    }

    fn navigation_started(&self, navigation: u64, uri: &str, cancelled: bool) {
        self.nav.borrow_mut().started(navigation, Url::parse(uri).ok(), cancelled);
        self.refresh();
    }

    fn navigation_completed(&self, navigation: u64) {
        self.nav.borrow_mut().completed(navigation);
        self.refresh();
    }

    /// Record the response when it answers the top-level navigation (never
    /// logged).
    fn response_received(&self, args: &ICoreWebView2WebResourceResponseReceivedEventArgs) {
        let read = || -> ::windows::core::Result<bool> {
            let mut uri = PWSTR::null();
            // SAFETY: COM reads on the event arguments WebView2 passed this
            // handler, on the UI thread; the out-pointer is a local and
            // `take_pwstr` frees the string.
            let uri = unsafe {
                args.Request()?.Uri(&mut uri)?;
                take_pwstr(uri)
            };
            let Ok(url) = Url::parse(&uri) else { return Ok(false) };
            if !self.nav.borrow().is_main_frame(&url) {
                return Ok(false);
            }
            // SAFETY: as above.
            let headers = unsafe { args.Response()?.Headers()? };
            let mime = header(&headers, w!("Content-Type"));
            let disposition = header(&headers, w!("Content-Disposition"));
            let Some(response) = linux_model::main_frame_response(Some(&uri), mime.as_deref(), disposition.as_deref())
            else {
                return Ok(false);
            };
            self.tracker.borrow_mut().record(response);
            Ok(true)
        };
        if read().unwrap_or(false) {
            self.refresh();
        }
    }

    /// Give keyboard focus back to the page after a click on the bar.
    fn focus_page(&self) {
        // SAFETY: a COM call on the controller, on the UI thread.
        let _ = unsafe { self.controller.MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC) };
    }

    /// A button click. Back / forward / reload are audited once each when
    /// WebView2 accepted them; each is a navigation, so the allow-list, TLS
    /// and HTTP-auth handlers run on it as on a page click.
    fn on_click(&self, action: NavAction) {
        let state = self.state.borrow().clone();
        let issued = match action {
            // SAFETY: a history call on the attached webview, on its UI thread.
            NavAction::Back if state.can_go_back => unsafe { self.core.GoBack() }.is_ok(),
            // SAFETY: a history call on the attached webview, on its UI thread.
            NavAction::Forward if state.can_go_forward => unsafe { self.core.GoForward() }.is_ok(),
            NavAction::Reload if !state.is_loading => {
                // Binding order (G5): mark before the reload starts, so the
                // fill engine skips the reload's own load.
                mark_operator_reload(&self.shared);
                // SAFETY: a reload of the attached webview, on its UI thread.
                let reloaded = unsafe { self.core.Reload() }.is_ok();
                if !reloaded {
                    // No load is coming: a mark left pending would make the
                    // fill engine skip a later, unrelated load.
                    super::clear_operator_reload(&self.shared);
                }
                reloaded
            }
            NavAction::Download if state.download_enabled() => {
                self.start_download();
                false
            }
            _ => false,
        };
        if issued {
            self.audit.nav(action);
        }
        self.focus_page();
    }

    fn refuse(&self, refusal: &'static str) {
        self.audit.download_refused(refusal);
        self.flash(refusal);
    }

    /// Audit an outcome settled on the UI thread, and flash a refusal.
    fn settle_here(&self, outcome: Option<Settled>) {
        if let Some(outcome) = outcome {
            audit_settled(&self.audit, &outcome);
            if let Settled::Refused(refusal) = outcome {
                self.flash(refusal);
            }
        }
    }

    /// What the window's TLS gate says about `url`'s origin.
    fn session_tls(&self, url: &Url) -> Option<SessionTls> {
        let gate = self.tls_pin.as_ref()?;
        let accepted_untrusted = WebOrigin::of_url(url).is_some_and(|o| gate.accepted_on_pin(&o));
        Some(SessionTls { has_pins: gate.has_pins(), accepted_untrusted })
    }

    fn cookie_manager(&self) -> Option<ICoreWebView2CookieManager> {
        // SAFETY: a COM read on the webview, on the UI thread.
        self.core2.as_ref().and_then(|core2| unsafe { core2.CookieManager() }.ok())
    }

    fn user_agent(&self) -> Option<String> {
        let mut agent = PWSTR::null();
        // SAFETY: COM reads on the webview's settings, on the UI thread; the
        // out-pointer is a local and `take_pwstr` frees the string.
        unsafe { self.core.Settings().ok()?.cast::<ICoreWebView2Settings2>().ok()?.UserAgent(&mut agent).ok()? };
        Some(take_pwstr(agent)).filter(|a| !a.is_empty())
    }

    /// The download click. Every refusal before the request is audited and
    /// nothing is requested.
    fn start_download(&self) {
        let Some(url) = self.shown_url() else { return self.refuse(reason::UNAVAILABLE) };
        // The same decision the webview's own downloads get (A6), before
        // anything is requested.
        if let Err(refusal) = transfer::url_policy(self.allow_downloads, &self.origins, &url) {
            return self.refuse(refusal);
        }
        // Then whether the bar's own request could be trusted and routed as
        // the page was.
        if let Err(refusal) = windows_model::refetch_gate(self.session_tls(&url), self.proxy_mode) {
            return self.refuse(refusal);
        }
        // The request goes straight to the origin; the webview follows the
        // system proxy. Any proxy configured there refuses it.
        if let Err(refusal) = windows_model::system_proxy_gate(system_proxy()) {
            return self.refuse(refusal);
        }
        let Some(cookies) = self.cookie_manager() else { return self.refuse(reason::UNAVAILABLE) };
        let Some(slot) = self.limiter.try_acquire() else { return self.refuse(reason::TOO_MANY_DOWNLOADS) };
        let Some(dest) = destination() else { return self.refuse(reason::SAVE_IO_ERROR) };
        let download = NEXT_DOWNLOAD.fetch_add(1, Ordering::Relaxed);
        let uri = HSTRING::from(url.as_str());
        let https = url.scheme() == "https";
        let waiting = Waiting { transfer: Transfer::new(slot, dest), url };
        self.downloads.borrow_mut().insert(download, InFlight::Cookies(Box::new(waiting)));
        let agent = self.user_agent();
        let bar_id = self.id;
        let handler = GetCookiesCompletedHandler::create(Box::new(move |result, list| {
            let cookies = match (result, list) {
                (Ok(()), Some(list)) => read_cookies(&list, https),
                _ => Err(reason::TRANSFER_FAILED),
            };
            with_bar(bar_id, |bar| bar.cookies_ready(download, cookies, agent));
            Ok(())
        }));
        // SAFETY: an asynchronous COM call on the webview's cookie manager,
        // on the UI thread; `uri` outlives the call and the completion runs
        // on this thread.
        if unsafe { cookies.GetCookies(&uri, &handler) }.is_err() {
            self.abandon(download, true);
        }
    }

    /// The webview's cookies for download `download` are in: start the
    /// request, or settle it.
    fn cookies_ready(
        &self,
        download: u64,
        cookies: Result<Option<Zeroizing<String>>, &'static str>,
        user_agent: Option<String>,
    ) {
        let entry = self.downloads.borrow_mut().remove(&download);
        let Some(InFlight::Cookies(waiting)) = entry else { return };
        let Waiting { mut transfer, url } = *waiting;
        let cookie = match cookies {
            Ok(cookie) => cookie,
            Err(refusal) => return self.settle_here(transfer.fail(refusal)),
        };
        let tls = match windows_refetch::platform_tls() {
            Ok(tls) => tls,
            Err(_) => {
                log::warn!("connect.web.nav_bar: the platform trust store could not be opened for a download");
                return self.settle_here(transfer.fail(reason::TRANSFER_FAILED));
            }
        };
        let (cancel, cancelled) = watch::channel(false);
        self.downloads.borrow_mut().insert(download, InFlight::Running { cancel });
        let refetch = Refetch { url, cookie, user_agent };
        let policy = Policy { allow_downloads: self.allow_downloads, origins: Arc::clone(&self.origins) };
        let audit = Arc::clone(&self.audit);
        let app = self.app.clone();
        let bar_id = self.id;
        tauri::async_runtime::spawn(async move {
            // The mark goes on the complete staging file, before it is moved
            // into Downloads, so the saved file is never unmarked.
            let settled = windows_refetch::run(refetch, transfer, policy, tls, cancelled, mark_of_the_web).await;
            // One audit line per download, written here even when the bar
            // is gone.
            audit_settled(&audit, &settled);
            let refusal = match settled {
                Settled::Refused(refusal) => Some(refusal),
                Settled::Saved(_) => None,
            };
            let _ = app.run_on_main_thread(move || {
                with_bar(bar_id, |bar| bar.download_finished(download, refusal));
            });
        });
    }

    fn download_finished(&self, download: u64, refusal: Option<&'static str>) {
        drop(self.downloads.borrow_mut().remove(&download));
        if let Some(refusal) = refusal {
            self.flash(refusal);
        }
    }

    /// End download `download` with `transfer_failed`: settled here while it
    /// waits for cookies, cancelled (and audited by its task) once running.
    fn abandon(&self, download: u64, flash: bool) {
        let entry = self.downloads.borrow_mut().remove(&download);
        match entry {
            Some(InFlight::Cookies(mut waiting)) => {
                let outcome = waiting.transfer.fail(reason::TRANSFER_FAILED);
                if flash {
                    self.settle_here(outcome);
                } else if let Some(outcome) = outcome {
                    audit_settled(&self.audit, &outcome);
                }
            }
            Some(InFlight::Running { cancel }) => {
                let _ = cancel.send(true);
            }
            None => {}
        }
    }

    // ── Teardown ──

    fn teardown(&self, window_gone: bool) {
        if self.torn_down.replace(true) {
            return;
        }
        let tokens = self.tokens.take();
        // SAFETY: undoing what `install` did, on the UI thread: the subclass
        // on the session window (still alive, also during its `WM_DESTROY`),
        // the webview's event registrations (an error from a webview that is
        // already closing is ignored), and the bar's own windows.
        unsafe {
            let _ = RemoveWindowSubclass(self.window, Some(parent_proc), self.subclass_id());
            if let Some(token) = tokens.history {
                let _ = self.core.remove_HistoryChanged(token);
            }
            if let Some(token) = tokens.source {
                let _ = self.core.remove_SourceChanged(token);
            }
            if let Some(token) = tokens.starting {
                let _ = self.core.remove_NavigationStarting(token);
            }
            if let Some(token) = tokens.completed {
                let _ = self.core.remove_NavigationCompleted(token);
            }
            if let (Some(core2), Some(token)) = (&self.core2, tokens.response) {
                let _ = core2.remove_WebResourceResponseReceived(token);
            }
            let _ = DestroyWindow(self.windows.tooltip);
            // Its buttons and status text go with it, and its flash timer.
            let _ = DestroyWindow(self.windows.bar);
        }
        if !window_gone && self.frame == WebviewFrame::ShrinkToFit {
            self.restore_webview();
        }
        let downloads: Vec<u64> = self.downloads.borrow().keys().copied().collect();
        for download in downloads {
            self.abandon(download, false);
        }
    }

    /// Give the webview the whole client area again, as wry left it.
    fn restore_webview(&self) {
        let mut client = RECT::default();
        // SAFETY: reads the session window's client area and moves wry's
        // container and controller back to it, on the UI thread.
        unsafe {
            if GetClientRect(self.window, &mut client).is_err() {
                return;
            }
            let (width, height) = (client.right - client.left, client.bottom - client.top);
            let _ = SetWindowPos(self.container, None, 0, 0, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
            let _ = self.controller.SetBounds(RECT { left: 0, top: 0, right: width, bottom: height });
        }
    }
}

/// One audit line for a settled download.
fn audit_settled(audit: &NavBarAudit, outcome: &Settled) {
    match outcome {
        Settled::Saved(saved) => audit.download_ok(&saved.filename, &saved.mime, saved.bytes, DownloadPath::Refetch),
        Settled::Refused(refusal) => audit.download_refused(refusal),
    }
}

/// The `Cookie` header from the webview's cookies for the request's URL. A
/// `Secure` cookie is dropped again on plain http (`https` false), whatever
/// `GetCookies` matched; one whose flag cannot be read counts as `Secure`.
fn read_cookies(list: &ICoreWebView2CookieList, https: bool) -> Result<Option<Zeroizing<String>>, &'static str> {
    let mut count = 0u32;
    // SAFETY: a COM read on the list WebView2 handed the completion handler,
    // on the UI thread.
    unsafe { list.Count(&mut count) }.map_err(|_| reason::TRANSFER_FAILED)?;
    let mut cookies: Vec<(String, Zeroizing<String>, bool)> = Vec::new();
    for index in 0..count.min(windows_model::MAX_COOKIES) {
        let mut name = PWSTR::null();
        let mut value = PWSTR::null();
        let mut secure = BOOL::from(true);
        // SAFETY: COM reads on the list and its cookies, on the UI thread;
        // the out-pointers are locals, each string is copied once and freed
        // (`take_pwstr`, and `take_secret`, which also wipes the value).
        let cookie = unsafe {
            let cookie = list.GetValueAtIndex(index).map_err(|_| reason::TRANSFER_FAILED)?;
            if cookie.IsSecure(&mut secure).is_err() {
                secure = BOOL::from(true);
            }
            cookie.Name(&mut name).map_err(|_| reason::TRANSFER_FAILED)?;
            let name = take_pwstr(name);
            cookie.Value(&mut value).map_err(|_| reason::TRANSFER_FAILED)?;
            (name, take_secret(value), secure.as_bool())
        };
        cookies.push(cookie);
    }
    let pairs = cookies.iter().map(|(name, value, secure)| (name.as_str(), value.as_str(), *secure));
    Ok(windows_model::cookie_header(https, pairs))
}

/// Mark a downloaded file as from the Internet (zone 3), as WebView2 marks
/// its own downloads. Called on the complete staging file, before it is
/// moved into Downloads: a rename keeps the stream and the cross-volume copy
/// (`CopyFileExW`) copies it. Failing to write it is logged and the download
/// goes on.
fn mark_of_the_web(file: &Path) {
    if let Err(e) = std::fs::write(windows_model::zone_identifier_path(file), windows_model::ZONE_IDENTIFIER) {
        log::warn!("connect.web.nav_bar: could not mark a download as from the internet ({:?})", e.kind());
    }
}

// ── Window procedures ──────────────────────────────────────────────

/// The session window's subclass: after the rest of the chain (wry's
/// subclass sizes the webview to the whole client area there), the bar
/// takes its strip back; on `WM_DESTROY` the bar is torn down.
extern "system" fn parent_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _subclass: usize,
    bar_id: usize,
) -> LRESULT {
    // SAFETY: the next procedure in the session window's chain, with this
    // message's own arguments, on the window's thread.
    let result = unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) };
    let id = bar_id as u64;
    match msg {
        WM_SIZE if wparam.0 != SIZE_MINIMIZED as usize => {
            with_bar(id, NativeBar::layout);
        }
        WM_DPICHANGED => {
            with_bar(id, NativeBar::layout);
        }
        WM_DESTROY => teardown(id, true),
        _ => {}
    }
    result
}

/// The bar window's procedure: button clicks, the flash timer and the
/// status text's colour.
extern "system" fn bar_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND if ((wparam.0 >> 16) & 0xFFFF) as u32 == BN_CLICKED => {
            let control = (wparam.0 & 0xFFFF) as u16;
            if let (Some(action), Some(bar)) = (windows_model::action_for_command(control), bar_of_window(hwnd)) {
                bar.on_click(action);
            }
            return LRESULT(0);
        }
        WM_TIMER if wparam.0 == FLASH_TIMER => {
            // SAFETY: stops the bar's own timer, on its thread.
            let _ = unsafe { KillTimer(Some(hwnd), FLASH_TIMER) };
            if let Some(bar) = bar_of_window(hwnd) {
                bar.end_flash();
            }
            return LRESULT(0);
        }
        WM_CTLCOLORSTATIC => {
            let alert = bar_of_window(hwnd).is_some_and(|bar| bar.flash.get().is_some());
            let hdc = HDC(wparam.0 as *mut c_void);
            // SAFETY: the device context the status text passed for this
            // paint, on its thread; the brush is a shared system one, never
            // deleted.
            let brush = unsafe {
                if alert {
                    SetTextColor(hdc, ALERT_TEXT);
                }
                SetBkMode(hdc, TRANSPARENT);
                GetSysColorBrush(COLOR_BTNFACE)
            };
            return LRESULT(brush.0 as isize);
        }
        _ => {}
    }
    // SAFETY: the default procedure, with this message's own arguments.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}
