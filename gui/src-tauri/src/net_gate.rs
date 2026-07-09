//! Network egress gate for `bvx.net_http` (Extensibility v2, Phase 5).
//!
//! Pure policy logic — no I/O, no Tauri — so it is exhaustively
//! unit-testable and (Phase 7) reusable by a server-side `bv.net_http`.
//! The caller (`plugin_apps::net_http`) does the DNS resolution and the
//! actual HTTPS request; this module answers three questions:
//!
//! 1. Is the URL's scheme/host/port allowed by the granted allowlist?
//! 2. For a matched host, are its resolved IPs safe (SSRF guard)?
//! 3. Same two checks again for every redirect `Location`.
//!
//! Grant semantics (mirrors `bastion_vault::plugins::grants`): an empty
//! grant list means "no network" — the caller returns `NET_NOT_GRANTED`
//! before ever calling here. Entries are exact hosts or a single
//! leading-label wildcard (`*.example.com`); ports are implicit 443
//! (https) / 80 (http).

use std::net::{IpAddr, Ipv6Addr};

/// Why a network request was refused. Maps to the guest return codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// No grant covers this request at all. Guest code `-6`.
    NotGranted,
    /// Scheme/host/port/redirect/SSRF refusal. Guest code `-7`.
    HostDenied,
}

/// A URL that passed scheme/host/port validation, plus the grant entry
/// it matched (needed for the http + private-IP exceptions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedTarget {
    pub host: String,
    /// The granted allowlist entry this host matched.
    pub matched_entry: String,
}

/// Return the granted allowlist entry that `host` matches, if any.
/// Exact match wins; otherwise a single leading-label wildcard
/// (`*.suffix`) matches any host ending in `.suffix` (≥ 1 label before).
pub fn match_host<'a>(host: &str, granted: &'a [String]) -> Option<&'a str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    // Exact matches first.
    for g in granted {
        if !g.starts_with("*.") && g.eq_ignore_ascii_case(&host) {
            return Some(g);
        }
    }
    for g in granted {
        if let Some(suffix) = g.strip_prefix("*.") {
            // `*.example.com` → host must end with `.example.com` and
            // have at least one non-empty label before the suffix.
            let dotted = format!(".{}", suffix.to_ascii_lowercase());
            if host.len() > dotted.len() && host.ends_with(&dotted) {
                return Some(g);
            }
        }
    }
    None
}

/// True when `host` is a bare IP literal (v4 or v6) rather than a name.
pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// True when an IP is loopback / private / link-local / ULA /
/// unspecified — i.e. must not be reached unless the admin explicitly
/// granted that literal address or a `.internal` name.
pub fn ip_is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // 100.64.0.0/10 (CGNAT) and 0.0.0.0/8 are also non-routable.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || is_unique_local_v6(v6)
                || is_link_local_v6(v6)
                // IPv4-mapped (::ffff:a.b.c.d) — re-check the embedded v4.
                || v6.to_ipv4_mapped().map(|m| ip_is_blocked(IpAddr::V4(m))).unwrap_or(false)
        }
    }
}

/// `fc00::/7` unique-local addresses.
fn is_unique_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// `fe80::/10` link-local addresses.
fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// Validate a request/redirect URL against the grant. Checks scheme,
/// host allowlist, and port. Does **not** resolve DNS — call
/// [`check_resolved_ips`] after resolving.
///
/// * `scheme` must be `https`. Plain `http` is allowed **only** when the
///   matched entry is an exact (non-wildcard) host *and* `https_only`
///   is false — a wildcard grant never authorizes cleartext.
/// * `port` must be the scheme default (443 / 80); an explicit port is
///   refused (the grant model has no port scoping).
pub fn validate_url(
    scheme: &str,
    host: Option<&str>,
    explicit_port: Option<u16>,
    granted: &[String],
    https_only: bool,
) -> Result<MatchedTarget, NetError> {
    if granted.is_empty() {
        return Err(NetError::NotGranted);
    }
    let host = host.ok_or(NetError::HostDenied)?;
    let matched = match_host(host, granted).ok_or(NetError::HostDenied)?;
    let exact_host = !matched.starts_with("*.");

    match scheme {
        "https" => {
            if let Some(p) = explicit_port {
                if p != 443 {
                    return Err(NetError::HostDenied);
                }
            }
        }
        "http" => {
            // Cleartext only for an exact host with https_only disabled.
            if https_only || !exact_host {
                return Err(NetError::HostDenied);
            }
            if let Some(p) = explicit_port {
                if p != 80 {
                    return Err(NetError::HostDenied);
                }
            }
        }
        _ => return Err(NetError::HostDenied),
    }

    Ok(MatchedTarget {
        host: host.to_ascii_lowercase(),
        matched_entry: matched.to_string(),
    })
}

/// SSRF guard: every resolved IP must be publicly routable, unless the
/// admin explicitly granted this exact target — i.e. the matched entry
/// equals the host **and** the host is either an IP literal or a
/// `.internal`-suffixed name the admin typed. A single blocked IP with
/// no such exception fails the whole request (defeats DNS tricks that
/// return one public + one private answer).
pub fn check_resolved_ips(
    target: &MatchedTarget,
    ips: &[IpAddr],
) -> Result<(), NetError> {
    if ips.is_empty() {
        return Err(NetError::HostDenied);
    }
    let explicitly_internal = target.matched_entry.eq_ignore_ascii_case(&target.host)
        && (is_ip_literal(&target.host) || target.host.ends_with(".internal"));
    for ip in ips {
        if ip_is_blocked(*ip) && !explicitly_internal {
            return Err(NetError::HostDenied);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exact_host_matches() {
        let grant = g(&["hooks.example.com"]);
        assert_eq!(match_host("hooks.example.com", &grant), Some("hooks.example.com"));
        assert_eq!(match_host("HOOKS.example.com", &grant), Some("hooks.example.com"));
        assert_eq!(match_host("evil.example.com", &grant), None);
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let grant = g(&["*.status.example.net"]);
        assert!(match_host("a.status.example.net", &grant).is_some());
        assert!(match_host("a.b.status.example.net", &grant).is_some());
        // The bare suffix itself is NOT matched by the wildcard.
        assert!(match_host("status.example.net", &grant).is_none());
        assert!(match_host("status.example.com", &grant).is_none());
    }

    #[test]
    fn blocked_ip_ranges() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:10.0.0.1", // v4-mapped private
        ] {
            assert!(ip_is_blocked(ip.parse().unwrap()), "{ip} should be blocked");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(!ip_is_blocked(ip.parse().unwrap()), "{ip} should be allowed");
        }
    }

    #[test]
    fn https_required_for_wildcard() {
        let grant = g(&["*.status.example.net"]);
        assert!(validate_url("https", Some("a.status.example.net"), None, &grant, true).is_ok());
        // http never allowed for a wildcard grant, even with https_only=false.
        assert_eq!(
            validate_url("http", Some("a.status.example.net"), None, &grant, false),
            Err(NetError::HostDenied)
        );
    }

    #[test]
    fn http_allowed_only_for_exact_host_with_flag() {
        let grant = g(&["internal.example.com"]);
        assert!(validate_url("http", Some("internal.example.com"), None, &grant, false).is_ok());
        // https_only=true refuses cleartext even for an exact host.
        assert_eq!(
            validate_url("http", Some("internal.example.com"), None, &grant, true),
            Err(NetError::HostDenied)
        );
    }

    #[test]
    fn explicit_nondefault_port_refused() {
        let grant = g(&["hooks.example.com"]);
        assert_eq!(
            validate_url("https", Some("hooks.example.com"), Some(8443), &grant, true),
            Err(NetError::HostDenied)
        );
        assert!(validate_url("https", Some("hooks.example.com"), Some(443), &grant, true).is_ok());
    }

    #[test]
    fn empty_grant_is_not_granted() {
        assert_eq!(
            validate_url("https", Some("x.com"), None, &[], true),
            Err(NetError::NotGranted)
        );
    }

    #[test]
    fn ssrf_blocks_private_resolution() {
        let grant = g(&["hooks.example.com"]);
        let t = validate_url("https", Some("hooks.example.com"), None, &grant, true).unwrap();
        // Public IP → ok.
        assert!(check_resolved_ips(&t, &["93.184.216.34".parse().unwrap()]).is_ok());
        // Rebinding: one public + one private answer → refused.
        assert_eq!(
            check_resolved_ips(
                &t,
                &["93.184.216.34".parse().unwrap(), "10.0.0.1".parse().unwrap()]
            ),
            Err(NetError::HostDenied)
        );
    }

    #[test]
    fn ssrf_allows_explicit_internal_name() {
        // Admin typed a `.internal` host verbatim → private IP allowed.
        let grant = g(&["db.internal"]);
        let t = validate_url("https", Some("db.internal"), None, &grant, true).unwrap();
        assert!(check_resolved_ips(&t, &["10.0.0.5".parse().unwrap()]).is_ok());
    }

    #[test]
    fn ssrf_allows_explicit_ip_literal_grant() {
        let grant = g(&["10.0.0.5"]);
        let t = validate_url("https", Some("10.0.0.5"), None, &grant, true).unwrap();
        assert!(check_resolved_ips(&t, &["10.0.0.5".parse().unwrap()]).is_ok());
    }
}
