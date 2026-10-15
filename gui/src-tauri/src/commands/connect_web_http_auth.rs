//! Native HTTP authentication challenge handlers for `http-auth` web
//! sessions (features/web-application-connect.md §7; T96 Phase 3).
//!
//! wry exposes no authentication-challenge callback, so the handler is
//! attached to the platform webview through `Webview::with_webview` (the
//! session's remote webview — with the Phase 5 toolbar the window holds two):
//!
//! | Platform | Hook |
//! |---|---|
//! | macOS   | `WKNavigationDelegate webView:didReceiveAuthenticationChallenge:completionHandler:` |
//! | Windows | WebView2 `BasicAuthenticationRequested` (+ `ClientCertificateRequested`, cancelled) |
//! | Linux   | WebKitGTK `authenticate` signal |
//!
//! This file is deliberately thin: it reads a platform challenge into a
//! [`Challenge`], asks [`HttpAuthGate::challenge`] (all policy lives there and
//! is unit-tested), and turns the [`GateAnswer`] into the platform's
//! disposition. It is only installed on `http-auth` session windows, so
//! `open` and `form` sessions keep the platform defaults exactly.
//!
//! Every refusal supplies no credential *and* suppresses the platform's own
//! prompt (WebView2 and WebKitGTK would otherwise show a login dialog), so a
//! refused challenge is never silently turned into "the operator types it".
//! Server trust is never answered by the HTTP-auth gate: it falls through to
//! the platform's default evaluation.
//!
//! **This is also the one attach point for the Phase 4 TLS pin handler**
//! (`commands/connect_web_tls_pin.rs`, decisions in `session::web_tls_pin`),
//! because on macOS both arrive through the same delegate method: WebKit
//! reports a TLS server-trust evaluation as one more authentication
//! challenge. A window gets the delegate when it has an HTTP-auth gate, a pin
//! gate, or both; on Windows and Linux the two are separate events and are
//! attached independently. A window with neither keeps the platform defaults
//! exactly.
//!
//! **Top-frame load failures (T139)** are reported from here too: the macOS
//! delegate's `didFail…Navigation` methods, WebView2's `NavigationCompleted`
//! and WebKitGTK's `load-failed`, each classified by `session::web_load` and
//! handed to the window's `TrustUi`.
//!
//! **The Windows and Linux blocks are not compiled on the development hosts
//! this was written on** (the Windows cross-check stops in C build scripts
//! before reaching this crate); both are kept minimal and are per-platform
//! manual checks.

use std::sync::Arc;

use tokio::sync::oneshot;

use crate::session::web_http_auth::HttpAuthGate;
use crate::session::web_tls_pin::TlsPinGate;

/// The native handlers one web session window needs. Neither set means
/// nothing to attach (and [`install`] is not called).
#[derive(Clone, Default)]
pub(crate) struct NativeGates {
    /// `http-auth` sessions (Phase 3).
    pub http_auth: Option<Arc<HttpAuthGate>>,
    /// Profiles carrying `tls_pin_sha256` (Phase 4). On macOS, Windows and
    /// Linux every session window has one (T139): without pins it asks the
    /// operator about a rejected certificate instead.
    pub tls_pin: Option<Arc<TlsPinGate>>,
    /// The operator-facing side (T139): the untrusted-certificate question
    /// and top-frame load failures.
    pub ui: Option<Arc<super::connect_web_trust_ui::TrustUi>>,
}

impl NativeGates {
    pub fn is_empty(&self) -> bool {
        self.ui.is_none() && self.http_auth.is_none() && self.tls_pin.is_none()
    }

    /// The abort check for a failure that cannot be told apart (the shared
    /// macOS delegate): the HTTP-auth handler's when there is one.
    #[cfg_attr(any(windows, target_os = "linux"), allow(dead_code))]
    fn shared_check(&self) -> &'static str {
        if self.http_auth.is_some() {
            HTTP_AUTH_HANDLER_CHECK
        } else {
            TLS_PIN_HANDLER_CHECK
        }
    }
}

/// `aborted:<check>` when the HTTP-auth handler could not be attached.
pub(crate) const HTTP_AUTH_HANDLER_CHECK: &str = "auth_handler";
/// `aborted:<check>` when the TLS pin handler could not be attached.
pub(crate) const TLS_PIN_HANDLER_CHECK: &str = "tls_handler";

/// A handler that could not be attached: which one (as its `aborted:<check>`
/// name) and a reason safe to show.
#[derive(Debug)]
pub(crate) struct InstallError {
    pub check: &'static str,
    pub reason: String,
}

impl InstallError {
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fn http_auth(reason: String) -> Self {
        Self { check: HTTP_AUTH_HANDLER_CHECK, reason }
    }

    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fn tls_pin(reason: String) -> Self {
        Self { check: TLS_PIN_HANDLER_CHECK, reason }
    }
}

/// Attach the gates to the remote webview `win`. Resolves once the platform
/// closure ran: `Ok` when every handler is in place, `Err` when one is not —
/// the caller must then not load the application.
pub(crate) fn install(win: &tauri::Webview, gates: NativeGates) -> oneshot::Receiver<Result<(), InstallError>> {
    let (tx, rx) = oneshot::channel();
    // If the closure never runs (the window is already gone), `tx` is
    // dropped with it and the receiver reports that.
    let _ = win.with_webview(move |webview| {
        let _ = tx.send(platform::install(webview, gates));
    });
    rx
}

// ── macOS ──────────────────────────────────────────────────────────

/// WKWebView asks its `navigationDelegate` for authentication challenges, and
/// wry installs its own delegate (`WryNavigationDelegate`) for the
/// navigation / new-window / download / page-load policy Phase 1 relies on.
///
/// **Approach: a forwarding proxy delegate, per webview.** A small class
/// implements only `webView:didReceiveAuthenticationChallenge:completionHandler:`
/// and forwards every other message to wry's delegate
/// (`respondsToSelector:` answers for both; `forwardingTargetForSelector:`
/// re-sends wry's selectors to wry's object, so wry's methods run with wry's
/// own `self`). It is set as the webview's delegate in place of wry's.
///
/// Rejected alternatives: replacing wry's delegate outright (loses the
/// Phase 1 policy); adding the method to wry's class at run time
/// (`class_addMethod`), which mutates a class every wry webview in the
/// process shares — the vault's own windows included; and isa-swizzling
/// wry's delegate object to a runtime subclass, which rewrites an object
/// another crate owns.
///
/// Lifetimes. WKWebView holds its delegate weakly, so the proxy is retained
/// as an associated object of **wry's delegate** (not of the webview, which
/// wry's delegate itself retains — that would be a cycle), and the proxy
/// holds wry's delegate weakly. The proxy therefore lives exactly as long as
/// wry's delegate; when that goes, the webview's weak delegate reference
/// clears and nothing calls into either. WebKit reads which optional methods
/// a delegate implements when it is set, so it is set once, after the proxy
/// is complete.
///
/// Routing (Phase 4). A server-trust challenge goes to the TLS pin shim when
/// the window has a pin gate, and to the platform's default evaluation
/// otherwise (exactly Phase 3). Every other challenge goes to the HTTP-auth
/// gate when the window has one; a pinned window without one answers it with
/// `RejectProtectionSpace`, which is what WebKit does for a delegate that
/// does not implement the method at all — so adding a pin changes nothing
/// but the server-trust path.
///
/// T139: every web session window now gets the proxy, with a pin gate that
/// may ask the operator about a rejected certificate when the profile has no
/// pins (the shim may then hold the challenge open — see
/// `connect_web_tls_pin::macos`). The proxy also implements the two
/// navigation-failure methods, which wry does not, to report a top-frame
/// load that failed; it forwards them to wry's delegate should a later wry
/// implement them.
#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::c_void;
    use std::sync::Arc;

    use block2::DynBlock;
    use objc2::rc::{Retained, Weak};
    use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject, Sel};
    use objc2::{define_class, msg_send, DefinedClass, MainThreadMarker, MainThreadOnly};
    use objc2_foundation::{
        NSString, NSURLAuthenticationChallenge, NSURLAuthenticationMethodClientCertificate,
        NSURLAuthenticationMethodHTTPBasic, NSURLAuthenticationMethodHTTPDigest, NSURLAuthenticationMethodNTLM,
        NSURLAuthenticationMethodNegotiate, NSURLAuthenticationMethodServerTrust, NSURLCredential,
        NSURLCredentialPersistence, NSURLSessionAuthChallengeDisposition,
    };
    use objc2_web_kit::{WKNavigationDelegate, WKWebView};

    use super::{InstallError, NativeGates};
    use crate::commands::connect_web_trust_ui::TrustUi;
    use crate::session::web_http_auth::{AuthMethod, Challenge, GateAnswer, HttpAuthGate};
    use crate::session::web_load::classify;
    use crate::session::web_tls_pin::TlsPinGate;

    pub struct ProxyIvars {
        http_auth: Option<Arc<HttpAuthGate>>,
        tls_pin: Option<Arc<TlsPinGate>>,
        ui: Option<Arc<TrustUi>>,
        /// wry's own delegate. Weak: the proxy is owned by it.
        inner: Weak<ProtocolObject<dyn WKNavigationDelegate>>,
    }

    define_class!(
        // SAFETY: NSObject has no subclassing requirements; the class adds no
        // `dealloc` and its ivars are plain Rust values dropped by objc2.
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        #[name = "BastionVaultChallengeNavigationDelegate"]
        #[ivars = ProxyIvars]
        struct HttpAuthNavigationDelegate;

        impl HttpAuthNavigationDelegate {
            /// Ours, or anything wry's delegate answers.
            // SAFETY: the signature matches `-[NSObject respondsToSelector:]`.
            #[unsafe(method(respondsToSelector:))]
            fn responds_to_selector(&self, selector: Sel) -> bool {
                // SAFETY: `super` is NSObject, which implements the method.
                let own: bool = unsafe { msg_send![super(self), respondsToSelector: selector] };
                own || self.ivars().inner.load().is_some_and(|inner| inner.respondsToSelector(selector))
            }

            /// Re-send everything the proxy does not implement to wry's
            /// delegate. Autoreleased, i.e. +0, as the runtime expects.
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
        unsafe impl NSObjectProtocol for HttpAuthNavigationDelegate {}

        // SAFETY: the one method below has the signature WebKit declares for
        // it (`objc2_web_kit::WKNavigationDelegate`).
        unsafe impl WKNavigationDelegate for HttpAuthNavigationDelegate {
            #[unsafe(method(webView:didReceiveAuthenticationChallenge:completionHandler:))]
            fn did_receive_challenge(
                &self,
                _web_view: &WKWebView,
                challenge: &NSURLAuthenticationChallenge,
                completion: &DynBlock<dyn Fn(NSURLSessionAuthChallengeDisposition, *mut NSURLCredential)>,
            ) {
                let ch = read_challenge(challenge);
                if ch.method == AuthMethod::ServerTrust {
                    match &self.ivars().tls_pin {
                        // Calls `completion`, now or once the operator answers.
                        Some(gate) => crate::commands::connect_web_tls_pin::macos::server_trust(
                            challenge,
                            gate,
                            self.ivars().ui.as_ref(),
                            completion,
                        ),
                        None => completion
                            .call((NSURLSessionAuthChallengeDisposition::PerformDefaultHandling, std::ptr::null_mut())),
                    }
                    return;
                }
                let Some(gate) = &self.ivars().http_auth else {
                    // What WebKit does when the delegate lacks this method.
                    completion.call((NSURLSessionAuthChallengeDisposition::RejectProtectionSpace, std::ptr::null_mut()));
                    return;
                };
                match gate.challenge(&ch) {
                    GateAnswer::Default => {
                        completion.call((NSURLSessionAuthChallengeDisposition::PerformDefaultHandling, std::ptr::null_mut()))
                    }
                    // Supply nothing and move on to the next protection space
                    // (a server offering Negotiate *and* Basic gets its Basic
                    // challenge next); with none left, the 401 page shows.
                    GateAnswer::Refuse(_) => {
                        completion.call((NSURLSessionAuthChallengeDisposition::RejectProtectionSpace, std::ptr::null_mut()))
                    }
                    GateAnswer::Answer(credential) => {
                        let user = NSString::from_str(credential.username());
                        let password = NSString::from_str(credential.password());
                        // `.forSession`: kept in this window's non-persistent
                        // store only — never `.permanent` (the keychain).
                        let ns = NSURLCredential::credentialWithUser_password_persistence(
                            &user,
                            &password,
                            NSURLCredentialPersistence::ForSession,
                        );
                        drop(credential);
                        completion.call((
                            NSURLSessionAuthChallengeDisposition::UseCredential,
                            Retained::as_ptr(&ns).cast_mut(),
                        ));
                    }
                }
            }

            /// A top-frame navigation failed before it committed (TLS, DNS,
            /// connection). WKWebView shows nothing for it.
            #[unsafe(method(webView:didFailProvisionalNavigation:withError:))]
            fn did_fail_provisional(&self, web_view: &WKWebView, navigation: *mut AnyObject, error: &AnyObject) {
                self.forward_failure(
                    objc2::sel!(webView:didFailProvisionalNavigation:withError:),
                    web_view,
                    navigation,
                    error,
                );
                self.report_failure(error);
            }

            /// A committed top-frame navigation failed while loading.
            #[unsafe(method(webView:didFailNavigation:withError:))]
            fn did_fail(&self, web_view: &WKWebView, navigation: *mut AnyObject, error: &AnyObject) {
                self.forward_failure(objc2::sel!(webView:didFailNavigation:withError:), web_view, navigation, error);
                self.report_failure(error);
            }
        }
    );

    impl HttpAuthNavigationDelegate {
        /// Hand a failure to wry's delegate too, if it implements the method
        /// (wry 0.55 does not).
        fn forward_failure(&self, selector: Sel, web_view: &WKWebView, navigation: *mut AnyObject, error: &AnyObject) {
            let Some(inner) = self.ivars().inner.load() else { return };
            if !inner.respondsToSelector(selector) {
                return;
            }
            // SAFETY: both selectors take (WKWebView *, WKNavigation *,
            // NSError *) and return void; `inner` answers the selector (checked
            // above); every argument is the one WebKit passed in.
            unsafe {
                if selector == objc2::sel!(webView:didFailProvisionalNavigation:withError:) {
                    let _: () = msg_send![&*inner, webView: web_view, didFailProvisionalNavigation: navigation, withError: error];
                } else {
                    let _: () = msg_send![&*inner, webView: web_view, didFailNavigation: navigation, withError: error];
                }
            }
        }

        /// Read the `NSError`'s domain, code and failing URL — never its
        /// description, which can carry the full URL — and report it.
        fn report_failure(&self, error: &AnyObject) {
            let Some(ui) = &self.ivars().ui else { return };
            // SAFETY: `error` is the `NSError` WebKit passed; `domain` returns
            // a non-null NSString, `code` an NSInteger, `userInfo` a
            // dictionary (possibly empty).
            let (domain, code, info): (Retained<NSString>, isize, Option<Retained<AnyObject>>) =
                unsafe { (msg_send![error, domain], msg_send![error, code], msg_send![error, userInfo]) };
            let domain = domain.to_string();
            let failing_url = info.and_then(|info| {
                let key = NSString::from_str("NSErrorFailingURLStringKey");
                // SAFETY: `objectForKey:` on the error's userInfo dictionary.
                let value: Option<Retained<AnyObject>> = unsafe { msg_send![&*info, objectForKey: &*key] };
                value.and_then(|v| v.downcast::<NSString>().ok()).map(|s| s.to_string())
            });
            let code = code as i64;
            ui.load_failed(failing_url.as_deref(), classify(&domain, code), &format!("{domain}:{code}"));
        }
    }

    fn method_of(method: &NSString) -> AuthMethod {
        // SAFETY: reading Foundation's immutable `NSString` constants.
        let known = unsafe {
            [
                (NSURLAuthenticationMethodHTTPBasic, AuthMethod::Basic),
                (NSURLAuthenticationMethodHTTPDigest, AuthMethod::Digest),
                (NSURLAuthenticationMethodNTLM, AuthMethod::Ntlm),
                (NSURLAuthenticationMethodNegotiate, AuthMethod::Negotiate),
                (NSURLAuthenticationMethodClientCertificate, AuthMethod::ClientCertificate),
                (NSURLAuthenticationMethodServerTrust, AuthMethod::ServerTrust),
            ]
        };
        known.iter().find(|(name, _)| method.isEqualToString(name)).map(|(_, m)| *m).unwrap_or(AuthMethod::Other)
    }

    fn read_challenge(challenge: &NSURLAuthenticationChallenge) -> Challenge {
        let space = challenge.protectionSpace();
        Challenge {
            method: method_of(&space.authenticationMethod()),
            scheme: space.protocol().map(|p| p.to_string()).unwrap_or_default(),
            host: space.host().to_string(),
            // An out-of-range port reads as 0, which never matches an origin.
            port: u16::try_from(space.port()).unwrap_or(0),
            realm: space.realm().map(|r| r.to_string()),
            is_proxy: space.isProxy(),
        }
    }

    /// Key for the associated object; only its address matters.
    static PROXY_KEY: u8 = 0;

    pub fn install(webview: tauri::webview::PlatformWebview, gates: NativeGates) -> Result<(), InstallError> {
        if gates.is_empty() {
            return Ok(());
        }
        let check = gates.shared_check();
        install_delegate(webview, gates).map_err(|reason| InstallError { check, reason })
    }

    fn install_delegate(webview: tauri::webview::PlatformWebview, gates: NativeGates) -> Result<(), String> {
        // SAFETY: `inner()` is a valid WKWebView, live for this call. We take
        // our own +1 with `retain` rather than adopting tauri's reference with
        // `from_raw`: tauri-runtime-wry 2.11 passes a leaked `into_raw` (+1),
        // but 2.12 passes `as_ptr` (+0), and `tauri = "2"` lets a routine
        // `cargo update` move between them. Adopting a +0 would over-release
        // the webview (use-after-free at close); `retain` is balanced under
        // both, and 2.11's leak stays tauri's. The controller and NSWindow
        // pointers are not used here, so they are not touched.
        let wk: Option<Retained<WKWebView>> = unsafe { Retained::retain(webview.inner().cast()) };
        let wk = wk.ok_or("the session window has no WKWebView")?;
        let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;

        // SAFETY: a plain property read on the main thread.
        let inner =
            unsafe { wk.navigationDelegate() }.ok_or("the session window has no navigation delegate to extend")?;
        let proxy = mtm.alloc::<HttpAuthNavigationDelegate>().set_ivars(ProxyIvars {
            http_auth: gates.http_auth,
            tls_pin: gates.tls_pin,
            ui: gates.ui,
            inner: Weak::from_retained(&inner),
        });
        // SAFETY: `init` on a freshly allocated NSObject subclass.
        let proxy: Retained<HttpAuthNavigationDelegate> = unsafe { msg_send![super(proxy), init] };

        // SAFETY: both pointers are live objects; the key is a static
        // address; RETAIN_NONATOMIC makes wry's delegate own the proxy
        // (released with it). Main thread, like every other use.
        unsafe {
            objc2::ffi::objc_setAssociatedObject(
                Retained::as_ptr(&inner).cast_mut().cast(),
                std::ptr::addr_of!(PROXY_KEY).cast::<c_void>(),
                Retained::as_ptr(&proxy).cast_mut().cast(),
                objc2::ffi::OBJC_ASSOCIATION_RETAIN_NONATOMIC,
            );
        }
        // SAFETY: setting a weak delegate property on the main thread, to an
        // object kept alive by the association above.
        unsafe { wk.setNavigationDelegate(Some(ProtocolObject::from_ref(&*proxy))) };
        Ok(())
    }
}

// ── Windows ────────────────────────────────────────────────────────

/// WebView2 raises `BasicAuthenticationRequested` for Basic, Digest, NTLM and
/// proxy authentication (`ICoreWebView2_10`, runtime 101+). The request URI
/// gives the origin (for proxy authentication it is the proxy's, which is
/// never in the scope); the `Challenge` text gives the scheme and realm.
/// Unanswered and uncancelled, WebView2 would show its own prompt, so every
/// refusal sets `Cancel`. Client-certificate requests are cancelled too, for
/// this window only. Server-certificate errors are the TLS pin shim's
/// (`connect_web_tls_pin`), attached only when the window has a pin gate.
#[cfg(windows)]
mod platform {
    use std::sync::Arc;

    use std::collections::VecDeque;
    use std::sync::Mutex;

    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2_10, ICoreWebView2_5, COREWEBVIEW2_WEB_ERROR_STATUS,
    };
    use webview2_com::{
        take_pwstr, BasicAuthenticationRequestedEventHandler, ClientCertificateRequestedEventHandler,
        NavigationCompletedEventHandler, NavigationStartingEventHandler,
    };
    use windows::core::{Interface, BOOL, PCWSTR, PWSTR};
    use zeroize::Zeroizing;

    use super::{InstallError, NativeGates};
    use crate::commands::connect_web_trust_ui::TrustUi;
    use crate::session::web_http_auth::{Challenge, GateAnswer, HttpAuthGate};
    use crate::session::web_load::classify_webview2;

    /// Navigations whose start is remembered to name a failure's origin.
    const STARTED_KEPT: usize = 16;

    /// A NUL-terminated UTF-16 copy that is zeroized when dropped.
    fn wide(s: &str) -> Zeroizing<Vec<u16>> {
        Zeroizing::new(s.encode_utf16().chain(std::iter::once(0)).collect())
    }

    pub fn install(webview: tauri::webview::PlatformWebview, gates: NativeGates) -> Result<(), InstallError> {
        if let Some(gate) = gates.http_auth {
            install_http_auth(&webview, gate).map_err(InstallError::http_auth)?;
        }
        if let Some(pins) = gates.tls_pin {
            crate::commands::connect_web_tls_pin::platform::install(&webview, pins, gates.ui.clone())
                .map_err(InstallError::tls_pin)?;
        }
        if let Some(ui) = gates.ui {
            install_load_failures(&webview, ui).map_err(InstallError::tls_pin)?;
        }
        Ok(())
    }

    /// Report a failed top-level navigation (T139). `NavigationCompleted`
    /// carries no URI, so the URI of each navigation's start is kept by id.
    fn install_load_failures(webview: &tauri::webview::PlatformWebview, ui: Arc<TrustUi>) -> Result<(), String> {
        let started: Arc<Mutex<VecDeque<(u64, String)>>> = Arc::new(Mutex::new(VecDeque::new()));
        let on_start = Arc::clone(&started);
        // SAFETY: COM calls on the WebView2 objects tauri hands this closure,
        // on the UI thread that owns them; every out-pointer is a local.
        unsafe {
            let core = webview.controller().CoreWebView2().map_err(|e| format!("CoreWebView2: {e}"))?;
            let starting = NavigationStartingEventHandler::create(Box::new(move |_, args| {
                let Some(args) = args else { return Ok(()) };
                let mut id = 0u64;
                let mut uri = PWSTR::null();
                args.NavigationId(&mut id)?;
                args.Uri(&mut uri)?;
                let mut kept = on_start.lock().unwrap_or_else(|p| p.into_inner());
                if kept.len() >= STARTED_KEPT {
                    kept.pop_front();
                }
                kept.push_back((id, take_pwstr(uri)));
                Ok(())
            }));
            let mut start_token = 0i64;
            core.add_NavigationStarting(&starting, &mut start_token)
                .map_err(|e| format!("add_NavigationStarting: {e}"))?;
            let completed = NavigationCompletedEventHandler::create(Box::new(move |_, args| {
                let Some(args) = args else { return Ok(()) };
                let mut id = 0u64;
                let mut success = BOOL::default();
                args.NavigationId(&mut id)?;
                args.IsSuccess(&mut success)?;
                let uri = {
                    let mut kept = started.lock().unwrap_or_else(|p| p.into_inner());
                    let at = kept.iter().position(|(i, _)| *i == id);
                    at.and_then(|at| kept.remove(at)).map(|(_, uri)| uri)
                };
                if success.as_bool() {
                    return Ok(());
                }
                let mut status = COREWEBVIEW2_WEB_ERROR_STATUS::default();
                args.WebErrorStatus(&mut status)?;
                ui.load_failed(uri.as_deref(), classify_webview2(status.0), &format!("webview2:{}", status.0));
                Ok(())
            }));
            let mut done_token = 0i64;
            core.add_NavigationCompleted(&completed, &mut done_token)
                .map_err(|e| format!("add_NavigationCompleted: {e}"))?;
        }
        Ok(())
    }

    fn install_http_auth(webview: &tauri::webview::PlatformWebview, gate: Arc<HttpAuthGate>) -> Result<(), String> {
        // SAFETY: COM calls on the WebView2 objects tauri hands this closure,
        // on the UI thread that owns them; every out-pointer is a local.
        unsafe {
            let core = webview.controller().CoreWebView2().map_err(|e| format!("CoreWebView2: {e}"))?;
            let core10 = core
                .cast::<ICoreWebView2_10>()
                .map_err(|e| format!("this WebView2 runtime cannot answer HTTP authentication (needs 101+): {e}"))?;
            let handler = BasicAuthenticationRequestedEventHandler::create(Box::new(move |_, args| {
                let Some(args) = args else { return Ok(()) };
                let answer = || -> windows::core::Result<()> {
                    let mut uri = PWSTR::null();
                    let mut header = PWSTR::null();
                    args.Uri(&mut uri)?;
                    args.Challenge(&mut header)?;
                    let ch = Challenge::from_uri_and_header(&take_pwstr(uri), &take_pwstr(header));
                    match gate.challenge(&ch) {
                        GateAnswer::Answer(credential) => {
                            let response = args.Response()?;
                            let user = wide(credential.username());
                            let password = wide(credential.password());
                            drop(credential);
                            response.SetUserName(PCWSTR(user.as_ptr()))?;
                            response.SetPassword(PCWSTR(password.as_ptr()))?;
                        }
                        // `BasicAuthenticationRequested` never carries server
                        // trust; cancel rather than let WebView2 prompt.
                        GateAnswer::Refuse(_) | GateAnswer::Default => args.SetCancel(true)?,
                    }
                    Ok(())
                };
                // Any COM failure above would otherwise return before
                // `SetCancel` and let WebView2 show its own prompt (possibly
                // with the username already set). Every failed path cancels
                // and is audited, like a refusal.
                if let Err(e) = answer() {
                    log::warn!(
                        target: "audit",
                        "connect.web.http_auth_refused: reason=auth_handler_error (WebView2 {:?})",
                        e.code()
                    );
                    args.SetCancel(true)?;
                }
                Ok(())
            }));
            let mut token = 0i64;
            core10
                .add_BasicAuthenticationRequested(&handler, &mut token)
                .map_err(|e| format!("add_BasicAuthenticationRequested: {e}"))?;

            if let Ok(core5) = core.cast::<ICoreWebView2_5>() {
                let cert = ClientCertificateRequestedEventHandler::create(Box::new(|_, args| {
                    if let Some(args) = args {
                        log::warn!(
                            target: "audit",
                            "connect.web.http_auth_refused: reason=auth_client_certificate (WebView2 client-certificate request)"
                        );
                        args.SetCancel(true)?;
                    }
                    Ok(())
                }));
                let mut cert_token = 0i64;
                core5
                    .add_ClientCertificateRequested(&cert, &mut cert_token)
                    .map_err(|e| format!("add_ClientCertificateRequested: {e}"))?;
            }
        }
        Ok(())
    }
}

// ── Linux ──────────────────────────────────────────────────────────

/// WebKitGTK emits `authenticate` on the web view. Returning `false` would
/// run WebKitGTK's default handler, which shows a login dialog, so every
/// HTTP-auth decision returns `true` after either authenticating or
/// cancelling; only server trust returns `false` (the default evaluation).
///
/// Not compiled on the hosts this was written on — see the module docs.
#[cfg(target_os = "linux")]
mod platform {
    use std::sync::Arc;

    use webkit2gtk::gio::{IOErrorEnum, ResolverError, TlsError};
    use webkit2gtk::glib::translate::ToGlibPtr;
    use webkit2gtk::{
        AuthenticationRequestExt, AuthenticationScheme, Credential, CredentialPersistence, NetworkError, PluginError,
        PolicyError, WebViewExt,
    };

    use super::{InstallError, NativeGates};
    use crate::commands::connect_web_trust_ui::TrustUi;
    use crate::session::web_http_auth::{AuthMethod, Challenge, GateAnswer, HttpAuthGate};
    use crate::session::web_load::{classify_webkitgtk, GtkErrorDomain};

    fn method_of(s: AuthenticationScheme) -> AuthMethod {
        match s {
            AuthenticationScheme::HttpBasic => AuthMethod::Basic,
            AuthenticationScheme::HttpDigest => AuthMethod::Digest,
            AuthenticationScheme::Ntlm => AuthMethod::Ntlm,
            AuthenticationScheme::Negotiate => AuthMethod::Negotiate,
            AuthenticationScheme::ClientCertificateRequested | AuthenticationScheme::ClientCertificatePinRequested => {
                AuthMethod::ClientCertificate
            }
            AuthenticationScheme::ServerTrustEvaluationRequested => AuthMethod::ServerTrust,
            _ => AuthMethod::Other,
        }
    }

    pub fn install(webview: tauri::webview::PlatformWebview, gates: NativeGates) -> Result<(), InstallError> {
        if let Some(gate) = gates.http_auth {
            install_http_auth(&webview, gate).map_err(InstallError::http_auth)?;
        }
        if let Some(pins) = gates.tls_pin {
            crate::commands::connect_web_tls_pin::platform::install(&webview, pins, gates.ui.clone())
                .map_err(InstallError::tls_pin)?;
        }
        if let Some(ui) = gates.ui {
            install_load_failures(&webview, ui);
        }
        Ok(())
    }

    /// The domain of a `load-failed` error, matched by type rather than by
    /// quark name.
    fn domain_of(error: &webkit2gtk::glib::Error) -> GtkErrorDomain {
        if error.is::<NetworkError>() {
            GtkErrorDomain::WebKitNetwork
        } else if error.is::<PolicyError>() {
            GtkErrorDomain::WebKitPolicy
        } else if error.is::<PluginError>() {
            GtkErrorDomain::WebKitPlugin
        } else if error.is::<IOErrorEnum>() {
            GtkErrorDomain::GIo
        } else if error.is::<ResolverError>() {
            GtkErrorDomain::GResolver
        } else if error.is::<TlsError>() {
            GtkErrorDomain::GTls
        } else {
            GtkErrorDomain::Other
        }
    }

    /// Report a failed main-resource load (T139). `load-failed` is emitted
    /// for the main resource only; returning `false` keeps WebKitGTK's own
    /// error page.
    fn install_load_failures(webview: &tauri::webview::PlatformWebview, ui: Arc<TrustUi>) {
        webview.inner().connect_load_failed(move |_, _event, failing_uri, error| {
            // SAFETY: reading the `code` field of the live `GError` behind
            // `error` (glib exposes the domain, not the code).
            let code = unsafe { (*ToGlibPtr::<*const webkit2gtk::glib::ffi::GError>::to_glib_none(error).0).code };
            let domain = domain_of(error);
            ui.load_failed(
                Some(failing_uri),
                classify_webkitgtk(domain, code),
                &format!("{}:{code}", error.domain().as_str()),
            );
            false
        });
    }

    fn install_http_auth(webview: &tauri::webview::PlatformWebview, gate: Arc<HttpAuthGate>) -> Result<(), String> {
        webview.inner().connect_authenticate(move |_, request| {
            let ch = Challenge {
                method: method_of(request.scheme()),
                scheme: request.security_origin().and_then(|o| o.protocol()).map(|p| p.to_string()).unwrap_or_default(),
                host: request.host().map(|h| h.to_string()).unwrap_or_default(),
                port: u16::try_from(request.port()).unwrap_or(0),
                realm: request.realm().map(|r| r.to_string()),
                is_proxy: request.is_for_proxy(),
            };
            match gate.challenge(&ch) {
                GateAnswer::Default => false,
                GateAnswer::Refuse(_) => {
                    request.cancel();
                    true
                }
                GateAnswer::Answer(credential) => {
                    let wk = Credential::new(
                        credential.username(),
                        credential.password(),
                        CredentialPersistence::ForSession,
                    );
                    drop(credential);
                    // SAFETY: `webkit_authentication_request_authenticate`
                    // (not wrapped by webkit2gtk 2.0) takes the request and a
                    // credential it copies; both pointers are live for the call.
                    unsafe {
                        webkit2gtk::ffi::webkit_authentication_request_authenticate(
                            request.to_glib_none().0,
                            ToGlibPtr::<*const webkit2gtk::ffi::WebKitCredential>::to_glib_none(&wk).0.cast_mut(),
                        );
                    }
                    true
                }
            }
        });
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
mod platform {
    use super::{InstallError, NativeGates};

    pub fn install(_webview: tauri::webview::PlatformWebview, gates: NativeGates) -> Result<(), InstallError> {
        // The operator-facing side needs a platform shim; without one the
        // window keeps the platform's behaviour.
        if gates.http_auth.is_none() && gates.tls_pin.is_none() {
            return Ok(());
        }
        Err(InstallError {
            check: gates.shared_check(),
            reason: "HTTP authentication challenges and TLS pins cannot be handled on this platform".into(),
        })
    }
}
