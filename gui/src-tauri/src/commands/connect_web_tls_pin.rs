//! TLS SPKI pinning for web sessions — the platform shims and the
//! fingerprint helper (features/web-application-connect.md §8; T96 Phase 4).
//!
//! Every decision is `session::web_tls_pin`'s; the shims here read the chain
//! a platform rejected, ask `TlsPinGate::server_trust`, and apply the
//! verdict. They are attached only to windows whose profile carries
//! `tls_pin_sha256` (through `connect_web_http_auth::install`, the single
//! native attach point), so an unpinned window keeps the platform's TLS
//! behaviour exactly.
//!
//! | Platform | Hook | Accept | Refuse |
//! |---|---|---|---|
//! | macOS   | server-trust challenge on the navigation delegate | `UseCredential` with `credentialForTrust:` | `CancelAuthenticationChallenge` |
//! | Windows | WebView2 `ServerCertificateErrorDetected` (`ICoreWebView2_14`) | `ALWAYS_ALLOW` (cached for this window's browser process) | `CANCEL` (no interstitial) |
//! | Linux   | WebKitGTK `load-failed-with-tls-errors` | per-context certificate exception for the host, then reload, once | `false` (WebKitGTK's error page) |
//!
//! None of them has an "accept any certificate" branch: the only accept is a
//! [`PinDecision::Accept`](crate::session::web_tls_pin::PinDecision) from the
//! gate, and any failure to read the chain is a refusal.
//!
//! The per-session scope of an accept: macOS answers one challenge on a
//! window whose `WKWebsiteDataStore` is non-persistent; WebView2's
//! `ALWAYS_ALLOW` is remembered by the browser process, which is per-window
//! (the per-session `data_directory`); WebKitGTK's exception lives in the
//! window's own ephemeral `WebContext` (wry creates one per incognito
//! webview). None outlives the session.
//!
//! **The Windows and Linux blocks are not compiled on the development hosts
//! this was written on** (see `connect_web_http_auth`); they are per-platform
//! manual checks.
//!
//! [`web_tls_fingerprint`] is the editor's trust-on-first-use helper: it
//! opens a TLS connection to an origin, records the chain the server
//! presents, finishes the handshake (which proves the server holds the
//! leaf's key) and closes. Nothing is sent over it and nothing is trusted by
//! it — the operator confirms the fingerprint in the editor.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use tauri::Url;

use crate::error::{CmdResult, CommandError};
use crate::session::web::WebOrigin;
use crate::session::web_tls_pin::{describe_chain, PresentedCertificate, MAX_CHAIN};

// ── macOS ──────────────────────────────────────────────────────────

/// The server-trust half of the navigation delegate in
/// `connect_web_http_auth` (WebKit has one challenge method for both).
///
/// A window may hold a challenge open while the operator is asked about an
/// untrusted certificate (T139). WebKit allows the completion handler to be
/// called later, and requires that it is called exactly once: a handler
/// released uncalled raises an Objective-C exception. So every held handler
/// lives in [`PENDING`] (main thread only) until [`resolve`] answers it or
/// [`cancel_pending`] — run when the window is destroyed — refuses it.
#[cfg(target_os = "macos")]
pub(crate) mod macos {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Arc;

    use block2::{DynBlock, RcBlock};
    use core_foundation::base::TCFType;
    use objc2::encode::{Encoding, RefEncode};
    use objc2::rc::Retained;
    use objc2::{msg_send, ClassType};
    use objc2_foundation::{NSURLAuthenticationChallenge, NSURLCredential, NSURLSessionAuthChallengeDisposition};
    use security_framework::trust::SecTrust;

    use crate::commands::connect_web_trust_ui::TrustUi;
    use crate::session::web::WebOrigin;
    use crate::session::web_load::LoadFailure;
    use crate::session::web_load::PageFailure;
    use crate::session::web_tls_pin::{describe_chain, OverrideVerdict, SpkiPin, TlsPinGate, MAX_CHAIN};

    /// `struct __SecTrust`, only ever behind a `SecTrustRef`.
    #[repr(C)]
    pub struct OpaqueSecTrust {
        _private: [u8; 0],
    }

    // SAFETY: the Objective-C type encoding of `SecTrustRef` is
    // `^{__SecTrust=}`, and this type is only used as that pointer's pointee,
    // so objc2's (debug) message-signature check sees the declared types of
    // `-[NSURLProtectionSpace serverTrust]` and
    // `+[NSURLCredential credentialForTrust:]`.
    unsafe impl RefEncode for OpaqueSecTrust {
        const ENCODING_REF: Encoding = Encoding::Pointer(&Encoding::Struct("__SecTrust", &[]));
    }

    pub(crate) type ChallengeCompletion = DynBlock<dyn Fn(NSURLSessionAuthChallengeDisposition, *mut NSURLCredential)>;
    type HeldCompletion = RcBlock<dyn Fn(NSURLSessionAuthChallengeDisposition, *mut NSURLCredential)>;

    const DEFAULT: NSURLSessionAuthChallengeDisposition = NSURLSessionAuthChallengeDisposition::PerformDefaultHandling;
    const CANCEL: NSURLSessionAuthChallengeDisposition =
        NSURLSessionAuthChallengeDisposition::CancelAuthenticationChallenge;

    /// One challenge held for the operator's answer.
    struct Held {
        completion: HeldCompletion,
        trust: SecTrust,
    }

    /// (window label, origin, leaf key): one question, however many
    /// connections WebKit opens to the origin while it is open.
    type PendingKey = (String, WebOrigin, SpkiPin);

    thread_local! {
        /// Main thread only: WebKit calls the delegate there, and
        /// [`resolve`] / [`cancel_pending`] are dispatched there.
        static PENDING: RefCell<HashMap<PendingKey, Vec<Held>>> = RefCell::new(HashMap::new());
    }

    /// The evaluated chain, leaf first, as DER.
    // `SecTrustGetCertificateAtIndex` is deprecated in favour of
    // `SecTrustCopyCertificateChain` (macOS 12), which security-framework only
    // exposes behind its `macos-12` feature; enabling it would change that
    // crate's feature set for every dependent in the graph. The deprecated
    // call is still supported and is only made after evaluation, as Apple
    // requires.
    #[allow(deprecated)]
    fn evaluated_chain(trust: &SecTrust) -> Vec<Vec<u8>> {
        let count = trust.certificate_count().clamp(0, MAX_CHAIN as isize);
        (0..count).filter_map(|i| trust.certificate_at_index(i)).map(|c| c.to_der()).collect()
    }

    /// `UseCredential` with a credential for `trust`, or cancel when none
    /// can be made.
    fn accept(trust: &SecTrust, completion: &ChallengeCompletion) {
        // SAFETY: a class method taking a live `SecTrustRef` (owned by
        // `trust` for this call); it returns an autoreleased credential (or
        // nil), which objc2 retains.
        let credential: Option<Retained<NSURLCredential>> = unsafe {
            msg_send![NSURLCredential::class(), credentialForTrust: trust.as_concrete_TypeRef().cast::<OpaqueSecTrust>()]
        };
        match credential {
            Some(c) => {
                completion.call((NSURLSessionAuthChallengeDisposition::UseCredential, Retained::as_ptr(&c).cast_mut()))
            }
            None => completion.call((CANCEL, std::ptr::null_mut())),
        }
    }

    /// Decide one server-trust challenge. Calls `completion` before
    /// returning, except when the operator is being asked; then the
    /// challenge is held in [`PENDING`] until the answer.
    ///
    /// 1. Not an https origin of the session → `PerformDefaultHandling` (the
    ///    platform decides; nothing evaluated here).
    /// 2. The platform's own evaluation passes → `PerformDefaultHandling`: a
    ///    pin or an operator override overrides rejections only
    ///    (`session::web_tls_pin`).
    /// 3. The profile has pins → the pins decide: accept → `UseCredential`
    ///    with a credential for this trust; anything else → cancel. A
    ///    mismatch is never offered to the operator.
    /// 4. No pins → the operator's answer for this exact key on this origin
    ///    this session: accepted → `UseCredential`; declined or unreadable →
    ///    cancel; not asked yet → ask (`ui`), or cancel without one.
    ///
    /// The evaluation in step 2 runs on the main thread, where WebKit calls
    /// its delegate. It is only made for the session's own origins.
    pub(crate) fn server_trust(
        challenge: &NSURLAuthenticationChallenge,
        gate: &Arc<TlsPinGate>,
        ui: Option<&Arc<TrustUi>>,
        completion: &ChallengeCompletion,
    ) {
        let space = challenge.protectionSpace();
        let origin = WebOrigin::from_parts(
            &space.protocol().map(|p| p.to_string()).unwrap_or_default(),
            &space.host().to_string(),
            // An out-of-range port reads as 0, which never matches an origin.
            u16::try_from(space.port()).unwrap_or(0),
        );
        if !gate.applies_to(origin.as_ref()) {
            completion.call((DEFAULT, std::ptr::null_mut()));
            return;
        }
        // `applies_to` holds only for a session origin.
        let Some(origin) = origin else {
            completion.call((DEFAULT, std::ptr::null_mut()));
            return;
        };
        // SAFETY: `-[NSURLProtectionSpace serverTrust]` returns the space's
        // `SecTrustRef` at +0, or NULL; it stays valid while `space` lives,
        // which is past the wrap below (which takes its own +1).
        let trust_ptr: *mut OpaqueSecTrust = unsafe { msg_send![&*space, serverTrust] };
        if trust_ptr.is_null() {
            // A server-trust challenge without a trust object: nothing to
            // pin against, and nothing to accept or show.
            if gate.has_pins() {
                let _ = gate.server_trust(Some(&origin), &[]);
            }
            completion.call((CANCEL, std::ptr::null_mut()));
            return;
        }
        // SAFETY: a valid `SecTrustRef` (checked non-null above);
        // `wrap_under_get_rule` takes its own +1 and releases it on drop.
        let trust = unsafe { SecTrust::wrap_under_get_rule(trust_ptr.cast()) };
        let platform_reason = match trust.evaluate_with_error() {
            Ok(()) => {
                completion.call((DEFAULT, std::ptr::null_mut()));
                return;
            }
            // Shown in the question only; it names the host and the
            // certificate, so it is never logged.
            Err(e) => e.to_string(),
        };
        let chain = evaluated_chain(&trust);

        if gate.has_pins() {
            let decision = gate.server_trust(Some(&origin), &chain).decision;
            match decision {
                d if d.accepts() => accept(&trust, completion),
                d => {
                    if let (Some(ui), crate::session::web_tls_pin::PinDecision::Refuse(r)) = (ui, d) {
                        ui.refused(&origin, PageFailure { check: r.check(), notice: r.notice() });
                    }
                    completion.call((CANCEL, std::ptr::null_mut()));
                }
            }
            return;
        }

        match gate.operator_override(Some(&origin), &chain) {
            OverrideVerdict::Accepted => accept(&trust, completion),
            OverrideVerdict::Declined => {
                if let Some(ui) = ui {
                    ui.refused(&origin, LoadFailure::TlsDeclined.page_failure());
                }
                completion.call((CANCEL, std::ptr::null_mut()));
            }
            OverrideVerdict::NotApplicable | OverrideVerdict::Unreadable => {
                completion.call((CANCEL, std::ptr::null_mut()))
            }
            OverrideVerdict::Ask(leaf) => {
                let Some(ui) = ui else {
                    completion.call((CANCEL, std::ptr::null_mut()));
                    return;
                };
                let key: PendingKey = (ui.label().to_string(), origin.clone(), leaf);
                let held = Held { completion: completion.copy(), trust };
                let first = PENDING.with(|p| {
                    let mut p = p.borrow_mut();
                    let waiting = p.entry(key.clone()).or_default();
                    waiting.push(held);
                    waiting.len() == 1
                });
                if !first {
                    // Already being asked about this key.
                    return;
                }
                let leaf_info = describe_chain(&chain).ok().and_then(|c| c.into_iter().next());
                let answer_ui = Arc::clone(ui);
                let answer_gate = Arc::clone(gate);
                ui.ask(&origin, leaf_info, Some(platform_reason), move |accepted| {
                    let app = answer_ui.app_handle();
                    let run = move || resolve(&key, accepted, &answer_gate, &answer_ui);
                    if let Err(e) = app.run_on_main_thread(run) {
                        // The event loop is gone: the process is exiting and
                        // the held handlers go with it.
                        log::warn!("connect.web.tls_override: could not deliver the answer: {e}");
                    }
                });
            }
        }
    }

    /// Answer every challenge held for `key`. Main thread.
    fn resolve(key: &PendingKey, accepted: bool, gate: &TlsPinGate, ui: &TrustUi) {
        let (_, origin, leaf) = key;
        let accepted = gate.record_override(origin, *leaf, accepted);
        if !accepted {
            ui.refused(origin, LoadFailure::TlsDeclined.page_failure());
        }
        let held = PENDING.with(|p| p.borrow_mut().remove(key)).unwrap_or_default();
        for h in held {
            if accepted {
                accept(&h.trust, &h.completion);
            } else {
                h.completion.call((CANCEL, std::ptr::null_mut()));
            }
        }
    }

    /// Refuse every challenge still held for the window `label` (it is being
    /// destroyed). Main thread.
    pub(crate) fn cancel_pending(label: &str) {
        let held: Vec<Held> = PENDING.with(|p| {
            let mut p = p.borrow_mut();
            let keys: Vec<PendingKey> = p.keys().filter(|(l, _, _)| l == label).cloned().collect();
            keys.into_iter().filter_map(|k| p.remove(&k)).flatten().collect()
        });
        for h in held {
            h.completion.call((CANCEL, std::ptr::null_mut()));
        }
    }
}

// ── Windows ────────────────────────────────────────────────────────

/// WebView2 raises `ServerCertificateErrorDetected` for every resource whose
/// certificate it cannot verify, after `WebResourceRequested`. The request
/// URI gives the origin; the certificate's PEM and its issuer chain give the
/// chain. Every path that is not an accept sets `CANCEL`, which also keeps
/// WebView2's interstitial (and any "continue anyway" it offers) away.
///
/// Not compiled on the hosts this was written on.
#[cfg(windows)]
pub(crate) mod platform {
    use std::sync::Arc;

    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2_14, COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_ALWAYS_ALLOW,
        COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL,
    };
    use webview2_com::{take_pwstr, ServerCertificateErrorDetectedEventHandler};
    use windows::core::{Interface, PWSTR};

    use crate::session::web::WebOrigin;
    use crate::session::web_tls_pin::{chain_from_pem, TlsPinGate, MAX_CHAIN};
    use tauri::Url;

    pub fn install(webview: &tauri::webview::PlatformWebview, gate: Arc<TlsPinGate>) -> Result<(), String> {
        // SAFETY: COM calls on the WebView2 objects tauri hands the
        // `with_webview` closure, on the UI thread that owns them; every
        // out-pointer is a local.
        unsafe {
            let core = webview.controller().CoreWebView2().map_err(|e| format!("CoreWebView2: {e}"))?;
            let core14 = core
                .cast::<ICoreWebView2_14>()
                .map_err(|e| format!("this WebView2 runtime cannot honour a TLS pin (no ICoreWebView2_14): {e}"))?;
            let handler = ServerCertificateErrorDetectedEventHandler::create(Box::new(move |_, args| {
                let Some(args) = args else { return Ok(()) };
                let decide = || -> windows::core::Result<bool> {
                    let mut uri = PWSTR::null();
                    args.RequestUri(&mut uri)?;
                    let uri = take_pwstr(uri);
                    let cert = args.ServerCertificate()?;
                    let mut leaf = PWSTR::null();
                    cert.ToPemEncoding(&mut leaf)?;
                    let leaf = take_pwstr(leaf);
                    let issuers = cert.PemEncodedIssuerCertificateChain()?;
                    let mut count = 0u32;
                    issuers.Count(&mut count)?;
                    let mut pems = Vec::new();
                    for i in 0..count.min(MAX_CHAIN as u32) {
                        let mut s = PWSTR::null();
                        issuers.GetValueAtIndex(i, &mut s)?;
                        pems.push(take_pwstr(s));
                    }
                    let origin = Url::parse(&uri).ok().as_ref().and_then(WebOrigin::of_url);
                    // An unreadable chain is decided as an empty one: refused
                    // on a session origin, never accepted.
                    let chain = chain_from_pem(&leaf, &pems).unwrap_or_default();
                    Ok(gate.server_trust(origin.as_ref(), &chain).decision.accepts())
                };
                let action = match decide() {
                    Ok(true) => COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_ALWAYS_ALLOW,
                    Ok(false) => COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL,
                    Err(e) => {
                        log::warn!(
                            target: "audit",
                            "connect.web.tls_pin_refused: reason=tls_handler (WebView2 {:?})",
                            e.code()
                        );
                        COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL
                    }
                };
                args.SetAction(action)?;
                Ok(())
            }));
            let mut token = 0i64;
            core14
                .add_ServerCertificateErrorDetected(&handler, &mut token)
                .map_err(|e| format!("add_ServerCertificateErrorDetected: {e}"))?;
        }
        Ok(())
    }
}

// ── Linux ──────────────────────────────────────────────────────────

/// WebKitGTK emits `load-failed-with-tls-errors` for a main-resource load
/// whose certificate failed verification. On an accept the certificate is
/// allowed for the host in this window's own `WebContext` and the load is
/// retried — once per (origin, key): a second failure with the same accepted
/// key means the exception did not take, and the error page stays. Returning
/// `false` leaves WebKitGTK's own error page, which offers no way past it.
///
/// Sub-resource loads do not raise the signal; they pass once the main
/// document of their host has been accepted (the exception is per host).
///
/// Not compiled on the hosts this was written on.
#[cfg(target_os = "linux")]
pub(crate) mod platform {
    use std::sync::Arc;

    use webkit2gtk::gio::prelude::TlsCertificateExt;
    use webkit2gtk::{WebContextExt, WebViewExt};

    use crate::session::web::WebOrigin;
    use crate::session::web_tls_pin::{TlsPinGate, MAX_CHAIN};
    use tauri::Url;

    pub fn install(webview: &tauri::webview::PlatformWebview, gate: Arc<TlsPinGate>) -> Result<(), String> {
        webview.inner().connect_load_failed_with_tls_errors(move |view, failing_uri, certificate, _errors| {
            let mut chain: Vec<Vec<u8>> = Vec::new();
            let mut next = Some(certificate.clone());
            while let Some(cert) = next.take() {
                if chain.len() >= MAX_CHAIN {
                    break;
                }
                let Some(der) = cert.certificate() else { break };
                chain.push(der.to_vec());
                next = cert.issuer();
            }
            let url = Url::parse(failing_uri).ok();
            let origin = url.as_ref().and_then(WebOrigin::of_url);
            let verdict = gate.server_trust(origin.as_ref(), &chain);
            if !verdict.decision.accepts() || !verdict.first {
                return false;
            }
            let (Some(context), Some(origin)) = (view.context(), origin) else { return false };
            let host = origin.host().trim_start_matches('[').trim_end_matches(']').to_string();
            context.allow_tls_certificate_for_host(certificate, &host);
            view.load_uri(failing_uri);
            true
        });
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
pub(crate) mod platform {
    use std::sync::Arc;

    use crate::session::web_tls_pin::TlsPinGate;

    pub fn install(_webview: &tauri::webview::PlatformWebview, _gate: Arc<TlsPinGate>) -> Result<(), String> {
        Err("TLS pins cannot be honoured on this platform".into())
    }
}

// ── Fingerprint helper (trust on first use) ────────────────────────

/// Connect, handshake and per-socket-operation budgets of one probe.
const PROBE_IO_TIMEOUT: Duration = Duration::from_secs(8);
/// The whole probe, DNS included.
const PROBE_BUDGET: Duration = Duration::from_secs(20);

#[derive(Deserialize)]
pub struct WebTlsFingerprintRequest {
    /// A start URL or an origin; only its origin is used. https only.
    pub url: String,
}

#[derive(Serialize)]
pub struct WebTlsFingerprintResponse {
    /// The origin probed.
    pub origin: String,
    /// What the server presented, leaf first.
    pub chain: Vec<PresentedCertificate>,
}

/// Records the chain the server presents and accepts it — for
/// [`probe_chain`] only, whose connection carries nothing and is closed right
/// after the handshake. The handshake signature is still verified with the
/// real algorithms, so a completed probe proves the server holds the leaf's
/// key. Never used for a session: the webviews do their own TLS.
#[derive(Debug)]
struct ChainRecorder {
    provider: Arc<CryptoProvider>,
    presented: Mutex<Option<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for ChainRecorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(1 + intermediates.len().min(MAX_CHAIN - 1));
        chain.push(end_entity.as_ref().to_vec());
        chain.extend(intermediates.iter().take(MAX_CHAIN - 1).map(|c| c.as_ref().to_vec()));
        *self.presented.lock().unwrap_or_else(|p| p.into_inner()) = Some(chain);
        // Trust on first use: shown to the operator, who decides.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Handshake with `host:port` and return the chain it presented. Blocking;
/// run off the async runtime.
fn probe_chain(host: &str, port: u16, io_timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
    use std::net::{TcpStream, ToSocketAddrs};

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let recorder = Arc::new(ChainRecorder { provider: Arc::clone(&provider), presented: Mutex::new(None) });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS configuration: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&recorder) as Arc<dyn ServerCertVerifier>)
        .with_no_client_auth();
    let name = ServerName::try_from(host)
        .map(|n| n.to_owned())
        .map_err(|e| format!("`{host}` is not a valid TLS server name: {e}"))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| format!("TLS client: {e}"))?;

    let addrs: Vec<_> = (host, port).to_socket_addrs().map_err(|e| format!("could not resolve {host}: {e}"))?.collect();
    let mut last_error = None;
    let mut sock = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, io_timeout) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let mut sock = sock.ok_or_else(|| {
        format!(
            "could not connect to {host}:{port}: {}",
            last_error.map(|e| e.to_string()).unwrap_or_else(|| "no address".to_string())
        )
    })?;
    sock.set_read_timeout(Some(io_timeout)).map_err(|e| format!("socket: {e}"))?;
    sock.set_write_timeout(Some(io_timeout)).map_err(|e| format!("socket: {e}"))?;

    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| format!("TLS handshake with {host}:{port} failed: {e}"))?;
    }
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    let chain = recorder.presented.lock().unwrap_or_else(|p| p.into_inner()).take();
    chain.ok_or_else(|| format!("{host}:{port} completed a handshake without presenting a certificate"))
}

/// The origin a fingerprint request may probe: https only, under the same
/// host rules as a profile's origins (no `localhost`, no trailing dot, no
/// userinfo).
fn probe_origin(raw: &str) -> Result<WebOrigin, String> {
    let url = Url::parse(raw.trim()).map_err(|e| format!("not a valid URL: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the URL carries userinfo (`user@host`)".to_string());
    }
    let origin = WebOrigin::validated(&url, false)?;
    if origin.scheme() != "https" {
        return Err("only https origins have a certificate to pin".to_string());
    }
    Ok(origin)
}

/// Fetch and show the certificate chain an https origin presents, with each
/// certificate's SPKI pin (spec §8, "fetch and show fingerprint").
///
/// **Trust on first use.** Nothing here makes the chain trustworthy: whoever
/// answers on the network path is who gets fingerprinted. The editor labels
/// it so and requires the operator to confirm before a pin is added; compare
/// it with the appliance's console when possible. No credential, vault data
/// or request is sent.
///
/// The probe connects directly (no proxy), speaks TLS 1.2 / 1.3 with rustls'
/// default cipher suites, and may therefore fail on an appliance the webview
/// can still reach (or differ from what a TLS-intercepting proxy shows the
/// webview).
#[tauri::command]
pub async fn web_tls_fingerprint(request: WebTlsFingerprintRequest) -> CmdResult<WebTlsFingerprintResponse> {
    let origin = probe_origin(&request.url).map_err(|e| CommandError::from(format!("fingerprint: {e}")))?;
    let host = origin.host().trim_start_matches('[').trim_end_matches(']').to_string();
    let port = origin.port();
    let probe = tauri::async_runtime::spawn_blocking(move || probe_chain(&host, port, PROBE_IO_TIMEOUT));
    let chain = match tokio::time::timeout(PROBE_BUDGET, probe).await {
        Ok(Ok(Ok(chain))) => chain,
        Ok(Ok(Err(e))) => return Err(CommandError::from(e)),
        Ok(Err(e)) => return Err(CommandError::from(format!("the fingerprint probe failed: {e}"))),
        Err(_) => return Err(CommandError::from(format!("{origin} did not complete a TLS handshake in time"))),
    };
    let described = describe_chain(&chain).map_err(CommandError::from)?;
    log::info!(
        target: "audit",
        "connect.web.tls_fingerprint: origin={origin} certificates={} leaf_pin={}",
        described.len(),
        described.first().map(|c| c.pin.as_str()).unwrap_or("none"),
    );
    Ok(WebTlsFingerprintResponse { origin: origin.to_string(), chain: described })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::web_tls_pin::SpkiPin;

    #[test]
    fn probe_origins_are_https_origins_under_the_profile_rules() {
        assert_eq!(probe_origin("https://fw01.example.com/login?x=1").unwrap().to_string(), "https://fw01.example.com");
        assert_eq!(probe_origin(" https://fw01.example.com:8443 ").unwrap().port(), 8443);
        for bad in [
            "http://fw01.example.com",
            "https://localhost:8443",
            "https://user@fw01.example.com",
            "https://fw01.example.com.",
            "ftp://fw01.example.com",
            "fw01.example.com",
            "",
        ] {
            assert!(probe_origin(bad).is_err(), "{bad}");
        }
    }

    /// End to end against a local rustls server presenting a self-signed
    /// appliance certificate: the probe records it, finishes the handshake
    /// and reports the SPKI pin the gate would match.
    #[test]
    fn the_probe_records_the_presented_chain_and_finishes_the_handshake() {
        use rcgen::{CertificateParams, KeyPair, PublicKeyData};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::net::TcpListener;

        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["fortigate.local".to_string()]).unwrap().self_signed(&key).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let server_config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut sock).is_err() {
                    return;
                }
            }
            let _ = conn.complete_io(&mut sock);
        });

        let chain = probe_chain("127.0.0.1", port, Duration::from_secs(5)).unwrap();
        server.join().unwrap();
        assert_eq!(chain, vec![cert_der]);
        let described = describe_chain(&chain).unwrap();
        assert_eq!(described[0].pin, SpkiPin::of_spki_der(&key.subject_public_key_info()).to_string());
        assert!(described[0].self_issued);
    }

    #[test]
    fn the_probe_reports_an_unreachable_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = probe_chain("127.0.0.1", port, Duration::from_secs(2)).unwrap_err();
        assert!(err.contains("could not connect"), "{err}");
    }
}
