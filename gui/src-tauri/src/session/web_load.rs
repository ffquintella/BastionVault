//! Top-frame load failures of a web session window
//! (features/web-application-connect.md §8.1, T139).
//!
//! WKWebView renders nothing for a navigation that fails before it commits —
//! an untrusted certificate, a host that does not resolve, a refused
//! connection — so without this the window stays blank and a form fill runs
//! into its deadline as `timeout`. WebView2 and WebKitGTK show their own
//! error page instead, but the fill still ran into its deadline. The platform
//! shim reads the failure's error domain and code and hands them to its
//! classifier ([`classify`] for WKWebView, [`classify_webview2`],
//! [`classify_webkitgtk`]); the session then shows the fixed
//! [`LoadFailure::notice`] in the title, audits [`LoadFailure::check`] and
//! ends the fill with `aborted:<check>`.
//!
//! Only the domain, the code and the failing origin are read. The platform's
//! localized description is never shown or logged: it can carry the full
//! URL, and a path or query can carry a token.

/// Why the top frame did not load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoadFailure {
    /// The platform rejected the server's certificate (untrusted root,
    /// expired, not yet valid, wrong host, not for TLS servers).
    TlsUntrusted,
    /// The operator was shown the untrusted certificate and declined it.
    TlsDeclined,
    /// The TLS handshake failed for another reason (protocol, client
    /// certificate requested or rejected).
    TlsHandshake,
    /// The host name did not resolve.
    Dns,
    /// The connection was refused or the host is unreachable.
    Connect,
    /// The server did not answer in time.
    Timeout,
    /// This machine has no network connection.
    Offline,
    /// The connection dropped, or another transport error.
    Network,
    /// Any other failure the platform reported.
    Other,
}

impl LoadFailure {
    /// The `aborted:<check>` name and audit reason (server rule:
    /// `[a-z0-9_]{1,32}`).
    pub fn check(self) -> &'static str {
        match self {
            Self::TlsUntrusted => "load_tls_untrusted",
            Self::TlsDeclined => "tls_declined",
            Self::TlsHandshake => "load_tls",
            Self::Dns => "load_dns",
            Self::Connect => "load_connect",
            Self::Timeout => "load_timeout",
            Self::Offline => "load_offline",
            Self::Network => "load_network",
            Self::Other => "load_failed",
        }
    }

    /// Operator-facing title text. Fixed text only.
    pub fn notice(self) -> &'static str {
        match self {
            Self::TlsUntrusted => "page not loaded: the TLS certificate is not trusted",
            Self::TlsDeclined => "page not loaded: untrusted TLS certificate declined",
            Self::TlsHandshake => "page not loaded: the TLS connection failed",
            Self::Dns => "page not loaded: the host name does not resolve",
            Self::Connect => "page not loaded: could not connect to the server",
            Self::Timeout => "page not loaded: the server did not answer in time",
            Self::Offline => "page not loaded: no network connection",
            Self::Network => "page not loaded: the connection was lost",
            Self::Other => "page not loaded",
        }
    }

    pub fn page_failure(self) -> PageFailure {
        PageFailure { check: self.check(), notice: self.notice() }
    }
}

/// What the session records for a page that did not load: the
/// `aborted:<check>` and the fixed title text. Built from a [`LoadFailure`]
/// or from a TLS pin refusal (`PinRefusal::check` / `notice`), whose more
/// precise reason wins over the platform's report of the same load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFailure {
    pub check: &'static str,
    pub notice: &'static str,
}

/// `NSURLErrorDomain`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const NS_URL_ERROR_DOMAIN: &str = "NSURLErrorDomain";
/// `WebKitErrorDomain`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const WEBKIT_ERROR_DOMAIN: &str = "WebKitErrorDomain";

/// Classify a failed top-frame navigation from its `NSError` domain and code.
/// `None` for the failures that are not the page's: a navigation cancelled
/// or superseded (`NSURLErrorCancelled`, which is also what a refused
/// server-trust challenge reports — see [`super::web::WebShared`]), and one
/// the navigation policy stopped (WebKit's "frame load interrupted").
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn classify(domain: &str, code: i64) -> Option<LoadFailure> {
    match domain {
        NS_URL_ERROR_DOMAIN => Some(match code {
            -999 => return None,
            // ServerCertificateHasBadDate, Untrusted, HasUnknownRoot,
            // NotYetValid.
            -1204..=-1201 => LoadFailure::TlsUntrusted,
            // SecureConnectionFailed, ClientCertificateRejected / Required.
            -1200 | -1205 | -1206 => LoadFailure::TlsHandshake,
            // CannotFindHost, DNSLookupFailed.
            -1003 | -1006 => LoadFailure::Dns,
            // CannotConnectToHost.
            -1004 => LoadFailure::Connect,
            -1001 => LoadFailure::Timeout,
            // NotConnectedToInternet, InternationalRoamingOff,
            // DataNotAllowed.
            -1009 | -1018 | -1020 => LoadFailure::Offline,
            // NetworkConnectionLost, BadServerResponse, cannot load from
            // network.
            -1005 | -1011 | -2000 => LoadFailure::Network,
            _ => LoadFailure::Other,
        }),
        // 102: frame load interrupted (a policy decision, including the
        // navigation allow-list's own refusals, which have their notice);
        // 204: handled by a plug-in.
        WEBKIT_ERROR_DOMAIN if code == 102 || code == 204 => None,
        _ => Some(LoadFailure::Other),
    }
}

/// Classify a failed WebView2 top-level navigation from its
/// `COREWEBVIEW2_WEB_ERROR_STATUS` (`NavigationCompleted` with
/// `IsSuccess == FALSE`). `None` for the outcomes that are not the page's:
///
/// * `OPERATION_CANCELED` — superseded or stopped, and what a certificate
///   this window refused (`ServerCertificateErrorDetected` → `CANCEL`) may
///   report; the window records its own refusal for that case.
/// * `UNKNOWN` — WebView2 also reports `IsSuccess == FALSE` for a page the
///   server answered with an HTTP error status, which rendered and is not a
///   load failure (WKWebView treats it as a success). Ambiguous, so not
///   reported: the recipe's own timeout still applies.
/// * the two "credentials required" statuses — an HTTP authentication
///   challenge the `http-auth` gate refused, which it reports itself.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn classify_webview2(status: i32) -> Option<LoadFailure> {
    Some(match status {
        0 | 14 | 17 | 18 => return None,
        // Common name incorrect, expired, revoked, invalid.
        1 | 2 | 4 | 5 => LoadFailure::TlsUntrusted,
        // Client certificate contains errors.
        3 => LoadFailure::TlsHandshake,
        // Server unreachable, cannot connect.
        6 | 12 => LoadFailure::Connect,
        7 => LoadFailure::Timeout,
        // The Internet connection has been lost.
        11 => LoadFailure::Offline,
        // Invalid server response, connection aborted, connection reset.
        8..=10 => LoadFailure::Network,
        13 => LoadFailure::Dns,
        // Redirect failed, unexpected error, anything newer.
        _ => LoadFailure::Other,
    })
}

/// The `GError` domains a WebKitGTK `load-failed` can carry. The shim maps
/// the error to one with `glib::Error::is`, so nothing here depends on a
/// quark's name.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtkErrorDomain {
    /// `WEBKIT_NETWORK_ERROR`.
    WebKitNetwork,
    /// `WEBKIT_POLICY_ERROR`.
    WebKitPolicy,
    /// `WEBKIT_PLUGIN_ERROR`.
    WebKitPlugin,
    /// `G_IO_ERROR` (libsoup 3 passes socket errors through).
    GIo,
    /// `G_RESOLVER_ERROR`.
    GResolver,
    /// `G_TLS_ERROR` (WebKitGTK's `load-failed` after an unhandled
    /// `load-failed-with-tls-errors` is `G_TLS_ERROR_BAD_CERTIFICATE`).
    GTls,
    Other,
}

/// Classify a failed WebKitGTK main-resource load (`load-failed`). `None`
/// for a cancelled or superseded load and for one the navigation policy
/// stopped (as [`classify`]).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn classify_webkitgtk(domain: GtkErrorDomain, code: i32) -> Option<LoadFailure> {
    Some(match domain {
        GtkErrorDomain::WebKitNetwork => match code {
            // WEBKIT_NETWORK_ERROR_CANCELLED.
            302 => return None,
            // WEBKIT_NETWORK_ERROR_TRANSPORT.
            300 => LoadFailure::Network,
            _ => LoadFailure::Other,
        },
        // FRAME_LOAD_INTERRUPTED_BY_POLICY_CHANGE (the allow-list's own
        // refusals, which have their notice).
        GtkErrorDomain::WebKitPolicy if code == 102 => return None,
        // WEBKIT_PLUGIN_ERROR_WILL_HANDLE_LOAD.
        GtkErrorDomain::WebKitPlugin if code == 204 => return None,
        GtkErrorDomain::GIo => match code {
            // G_IO_ERROR_CANCELLED.
            19 => return None,
            24 => LoadFailure::Timeout,
            // HOST_NOT_FOUND.
            28 => LoadFailure::Dns,
            // HOST_UNREACHABLE, CONNECTION_REFUSED.
            37 | 39 => LoadFailure::Connect,
            // NETWORK_UNREACHABLE.
            38 => LoadFailure::Offline,
            // CONNECTION_CLOSED / BROKEN_PIPE, NOT_CONNECTED.
            44 | 45 => LoadFailure::Network,
            _ => LoadFailure::Other,
        },
        GtkErrorDomain::GResolver => LoadFailure::Dns,
        GtkErrorDomain::GTls => match code {
            // G_TLS_ERROR_BAD_CERTIFICATE.
            2 => LoadFailure::TlsUntrusted,
            _ => LoadFailure::TlsHandshake,
        },
        GtkErrorDomain::WebKitPolicy | GtkErrorDomain::WebKitPlugin | GtkErrorDomain::Other => LoadFailure::Other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webview2_statuses_are_named() {
        for s in [1, 2, 4, 5] {
            assert_eq!(classify_webview2(s), Some(LoadFailure::TlsUntrusted), "{s}");
        }
        assert_eq!(classify_webview2(3), Some(LoadFailure::TlsHandshake));
        assert_eq!(classify_webview2(13), Some(LoadFailure::Dns));
        assert_eq!(classify_webview2(12), Some(LoadFailure::Connect));
        assert_eq!(classify_webview2(6), Some(LoadFailure::Connect));
        assert_eq!(classify_webview2(7), Some(LoadFailure::Timeout));
        assert_eq!(classify_webview2(11), Some(LoadFailure::Offline));
        assert_eq!(classify_webview2(10), Some(LoadFailure::Network));
        assert_eq!(classify_webview2(16), Some(LoadFailure::Other));
        assert_eq!(classify_webview2(99), Some(LoadFailure::Other));
    }

    #[test]
    fn webview2_cancels_http_errors_and_auth_are_not_failures() {
        for s in [0, 14, 17, 18] {
            assert_eq!(classify_webview2(s), None, "{s}");
        }
    }

    #[test]
    fn webkitgtk_errors_are_named() {
        use GtkErrorDomain::*;
        assert_eq!(classify_webkitgtk(GTls, 2), Some(LoadFailure::TlsUntrusted));
        assert_eq!(classify_webkitgtk(GTls, 4), Some(LoadFailure::TlsHandshake));
        assert_eq!(classify_webkitgtk(GResolver, 0), Some(LoadFailure::Dns));
        assert_eq!(classify_webkitgtk(GIo, 28), Some(LoadFailure::Dns));
        assert_eq!(classify_webkitgtk(GIo, 39), Some(LoadFailure::Connect));
        assert_eq!(classify_webkitgtk(GIo, 37), Some(LoadFailure::Connect));
        assert_eq!(classify_webkitgtk(GIo, 24), Some(LoadFailure::Timeout));
        assert_eq!(classify_webkitgtk(GIo, 38), Some(LoadFailure::Offline));
        assert_eq!(classify_webkitgtk(GIo, 44), Some(LoadFailure::Network));
        assert_eq!(classify_webkitgtk(GIo, 1), Some(LoadFailure::Other));
        assert_eq!(classify_webkitgtk(WebKitNetwork, 300), Some(LoadFailure::Network));
        assert_eq!(classify_webkitgtk(WebKitNetwork, 399), Some(LoadFailure::Other));
        assert_eq!(classify_webkitgtk(WebKitPolicy, 101), Some(LoadFailure::Other));
        assert_eq!(classify_webkitgtk(Other, 7), Some(LoadFailure::Other));
    }

    #[test]
    fn webkitgtk_cancelled_and_policy_interrupted_loads_are_not_failures() {
        use GtkErrorDomain::*;
        assert_eq!(classify_webkitgtk(WebKitNetwork, 302), None);
        assert_eq!(classify_webkitgtk(GIo, 19), None);
        assert_eq!(classify_webkitgtk(WebKitPolicy, 102), None);
        assert_eq!(classify_webkitgtk(WebKitPlugin, 204), None);
    }

    #[test]
    fn certificate_errors_are_untrusted() {
        for code in [-1201, -1202, -1203, -1204] {
            assert_eq!(classify(NS_URL_ERROR_DOMAIN, code), Some(LoadFailure::TlsUntrusted), "{code}");
        }
        assert_eq!(classify(NS_URL_ERROR_DOMAIN, -1200), Some(LoadFailure::TlsHandshake));
        assert_eq!(classify(NS_URL_ERROR_DOMAIN, -1206), Some(LoadFailure::TlsHandshake));
    }

    #[test]
    fn network_errors_are_named() {
        assert_eq!(classify(NS_URL_ERROR_DOMAIN, -1003), Some(LoadFailure::Dns));
        assert_eq!(classify(NS_URL_ERROR_DOMAIN, -1004), Some(LoadFailure::Connect));
        assert_eq!(classify(NS_URL_ERROR_DOMAIN, -1001), Some(LoadFailure::Timeout));
        assert_eq!(classify(NS_URL_ERROR_DOMAIN, -1009), Some(LoadFailure::Offline));
        assert_eq!(classify(NS_URL_ERROR_DOMAIN, -1005), Some(LoadFailure::Network));
        assert_eq!(classify(NS_URL_ERROR_DOMAIN, -1), Some(LoadFailure::Other));
        assert_eq!(classify("SomeOtherDomain", 7), Some(LoadFailure::Other));
    }

    #[test]
    fn cancelled_and_policy_interrupted_loads_are_not_failures() {
        assert_eq!(classify(NS_URL_ERROR_DOMAIN, -999), None);
        assert_eq!(classify(WEBKIT_ERROR_DOMAIN, 102), None);
        assert_eq!(classify(WEBKIT_ERROR_DOMAIN, 204), None);
        assert_eq!(classify(WEBKIT_ERROR_DOMAIN, 101), Some(LoadFailure::Other));
    }

    #[test]
    fn checks_fit_the_server_rule() {
        let all = [
            LoadFailure::TlsUntrusted,
            LoadFailure::TlsDeclined,
            LoadFailure::TlsHandshake,
            LoadFailure::Dns,
            LoadFailure::Connect,
            LoadFailure::Timeout,
            LoadFailure::Offline,
            LoadFailure::Network,
            LoadFailure::Other,
        ];
        for f in all {
            let c = f.check();
            assert!(!c.is_empty() && c.len() <= 32, "{c}");
            assert!(c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'), "{c}");
            assert!(f.notice().starts_with("page not loaded"), "{}", f.notice());
        }
    }
}
