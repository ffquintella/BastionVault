//! Native HTTP authentication challenge handlers for `http-auth` web
//! sessions (features/web-application-connect.md §7; T96 Phase 3).
//!
//! wry exposes no authentication-challenge callback, so the handler is
//! attached to the platform webview through `WebviewWindow::with_webview`:
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
//! Server trust is never answered here: it falls through to the platform's
//! default evaluation (Phase 4 owns pinning).
//!
//! **The Windows and Linux blocks are not compiled on the development hosts
//! this was written on** (the Windows cross-check stops in C build scripts
//! before reaching this crate); both are kept minimal and are per-platform
//! manual checks.

use std::sync::Arc;

use tokio::sync::oneshot;

use crate::session::web_http_auth::HttpAuthGate;

/// Attach the gate to `win`'s webview. Resolves once the platform closure
/// ran: `Ok` when the handler is in place, `Err` (with a reason safe to show)
/// when it is not — the caller must then not load the application.
pub(crate) fn install(win: &tauri::WebviewWindow, gate: Arc<HttpAuthGate>) -> oneshot::Receiver<Result<(), String>> {
    let (tx, rx) = oneshot::channel();
    // If the closure never runs (the window is already gone), `tx` is
    // dropped with it and the receiver reports that.
    let _ = win.with_webview(move |webview| {
        let _ = tx.send(platform::install(webview, gate));
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

    use crate::session::web_http_auth::{AuthMethod, Challenge, GateAnswer, HttpAuthGate};

    pub struct ProxyIvars {
        gate: Arc<HttpAuthGate>,
        /// wry's own delegate. Weak: the proxy is owned by it.
        inner: Weak<ProtocolObject<dyn WKNavigationDelegate>>,
    }

    define_class!(
        // SAFETY: NSObject has no subclassing requirements; the class adds no
        // `dealloc` and its ivars are plain Rust values dropped by objc2.
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        #[name = "BastionVaultHttpAuthNavigationDelegate"]
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
                match self.ivars().gate.challenge(&ch) {
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
        }
    );

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

    pub fn install(webview: tauri::webview::PlatformWebview, gate: Arc<HttpAuthGate>) -> Result<(), String> {
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
        let proxy = mtm
            .alloc::<HttpAuthNavigationDelegate>()
            .set_ivars(ProxyIvars { gate, inner: Weak::from_retained(&inner) });
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
/// this window only. Server-certificate errors are not touched.
#[cfg(windows)]
mod platform {
    use std::sync::Arc;

    use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2_10, ICoreWebView2_5};
    use webview2_com::{take_pwstr, BasicAuthenticationRequestedEventHandler, ClientCertificateRequestedEventHandler};
    use windows::core::{Interface, PCWSTR, PWSTR};
    use zeroize::Zeroizing;

    use crate::session::web_http_auth::{Challenge, GateAnswer, HttpAuthGate};

    /// A NUL-terminated UTF-16 copy that is zeroized when dropped.
    fn wide(s: &str) -> Zeroizing<Vec<u16>> {
        Zeroizing::new(s.encode_utf16().chain(std::iter::once(0)).collect())
    }

    pub fn install(webview: tauri::webview::PlatformWebview, gate: Arc<HttpAuthGate>) -> Result<(), String> {
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

    use webkit2gtk::glib::translate::ToGlibPtr;
    use webkit2gtk::{AuthenticationRequestExt, AuthenticationScheme, Credential, CredentialPersistence, WebViewExt};

    use crate::session::web_http_auth::{AuthMethod, Challenge, GateAnswer, HttpAuthGate};

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

    pub fn install(webview: tauri::webview::PlatformWebview, gate: Arc<HttpAuthGate>) -> Result<(), String> {
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
    use std::sync::Arc;

    use crate::session::web_http_auth::HttpAuthGate;

    pub fn install(_webview: tauri::webview::PlatformWebview, _gate: Arc<HttpAuthGate>) -> Result<(), String> {
        Err("HTTP authentication challenges cannot be answered on this platform".into())
    }
}
