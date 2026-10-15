//! Top-frame load failures of a web session window
//! (features/web-application-connect.md §8.1, T139).
//!
//! WKWebView renders nothing for a navigation that fails before it commits —
//! an untrusted certificate, a host that does not resolve, a refused
//! connection — so without this the window stays blank and a form fill runs
//! into its deadline as `timeout`. The platform shim reads the failure's
//! error domain and code and hands them to [`classify`]; the session then
//! shows the fixed [`LoadFailure::notice`] in the title, audits
//! [`LoadFailure::check`] and ends the fill with `aborted:<check>`.
//!
//! Only the domain, the code and the failing origin are read. The platform's
//! localized description is never shown or logged: it can carry the full
//! URL, and a path or query can carry a token.

// Only the macOS WKWebView shim calls into this module (T139).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

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
pub const NS_URL_ERROR_DOMAIN: &str = "NSURLErrorDomain";
/// `WebKitErrorDomain`.
pub const WEBKIT_ERROR_DOMAIN: &str = "WebKitErrorDomain";

/// Classify a failed top-frame navigation from its `NSError` domain and code.
/// `None` for the failures that are not the page's: a navigation cancelled
/// or superseded (`NSURLErrorCancelled`, which is also what a refused
/// server-trust challenge reports — see [`super::web::WebShared`]), and one
/// the navigation policy stopped (WebKit's "frame load interrupted").
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

#[cfg(test)]
mod tests {
    use super::*;

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
