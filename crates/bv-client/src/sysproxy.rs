//! System-proxy resolution across platforms.
//!
//! `ureq`'s built-in "system proxy" support only reads the
//! `ALL_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` environment variables and,
//! on Windows (with the `win-system-proxy` feature), the WinINET
//! registry. It has **no** knowledge of the macOS *System Settings →
//! Network → Proxies* pane or the GNOME proxy settings on Linux, so a
//! user who configures a proxy there sees the "Use system proxy" toggle
//! do nothing.
//!
//! [`system_proxy_uri`] fills exactly that gap. It returns a proxy URI
//! (`http://host:port` / `socks5://host:port`) for the sources ureq's own
//! detection misses, and `None` when either nothing is configured or the
//! configuration is already covered by ureq's default detection (env
//! vars on every platform, the registry on Windows).
//!
//! Precedence deliberately mirrors ureq: an explicit proxy environment
//! variable wins over the OS GUI settings, so scripted/CI overrides keep
//! working. Callers only consult this helper when the operator has opted
//! into honouring the system proxy; with the toggle off the proxy is
//! cleared unconditionally so vault traffic is never silently rerouted.

/// Resolve a system proxy URI for the sources ureq cannot read on its own.
///
/// Returns `Some(uri)` only when the proxy comes from a source ureq's
/// default detection would miss — today the macOS System Settings pane
/// and the GNOME (`gsettings`) configuration on Linux. Returns `None`
/// when:
///
/// * a proxy environment variable is set (ureq's own default already
///   honours it, and env vars take precedence over GUI settings), or
/// * the platform's GUI proxy is unset / unsupported (Windows registry
///   is handled by ureq's `win-system-proxy` feature, so this helper
///   defers to it there).
///
/// The returned URI is suitable for [`ureq::Proxy::new`]. HTTPS/secure
/// web proxies are preferred (BastionVault speaks TLS by default),
/// falling back to a plain HTTP proxy and then SOCKS.
pub fn system_proxy_uri() -> Option<String> {
    // An explicit environment proxy wins and is already honoured by
    // ureq's default `Proxy::try_from_env()`, so we must not shadow it.
    if env_proxy().is_some() {
        return None;
    }
    platform_proxy_uri()
}

/// Proxy environment variables ureq reads, in `Proxy::try_from_env`'s
/// precedence order (and matching its case handling).
const ENV_VARS: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// The first proxy environment variable that is set to a non-empty value,
/// as `(var_name, value)`.
fn env_proxy() -> Option<(&'static str, String)> {
    for var in ENV_VARS {
        if let Ok(val) = std::env::var(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some((var, trimmed.to_string()));
            }
        }
    }
    None
}

/// Human-readable description of the proxy an opted-in client will use,
/// for diagnostics and the connect dialog's "Test proxy" button.
///
/// Returns `(source, uri)`:
/// * `source` — where the proxy came from, e.g. `"environment variable
///   HTTPS_PROXY"`, `"system network settings"`, or `"no proxy configured
///   (direct connection)"`.
/// * `uri` — the resolved proxy URI, or `None` for a direct connection.
///
/// Mirrors [`system_proxy_uri`]'s precedence (env vars first) but also
/// reports the environment case, which `system_proxy_uri` defers to ureq
/// for.
pub fn describe_system_proxy() -> (String, Option<String>) {
    if let Some((var, val)) = env_proxy() {
        return (format!("environment variable {var}"), Some(val));
    }
    match platform_proxy_uri() {
        Some(uri) => ("system network settings".to_string(), Some(uri)),
        None => (
            "no proxy configured (direct connection)".to_string(),
            None,
        ),
    }
}

#[cfg(target_os = "macos")]
fn platform_proxy_uri() -> Option<String> {
    // `scutil --proxy` dumps the active System Settings network proxy
    // dictionary as plain text. Parsing its output avoids a dependency
    // on the SystemConfiguration framework bindings.
    let output = std::process::Command::new("scutil")
        .arg("--proxy")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_scutil_proxy(&text)
}

/// Parse the `scutil --proxy` dictionary text into a proxy URI.
///
/// The dictionary contains `<Scheme>Enable`, `<Scheme>Proxy` and
/// `<Scheme>Port` entries for `HTTPS`, `HTTP` and `SOCKS`. A PAC
/// (`ProxyAutoConfig`) or WPAD setup cannot be reduced to a single URI
/// and is intentionally not handled here (returns `None`).
///
/// Kept as a pure function so it can be unit-tested against captured
/// `scutil` output without touching the real system.
#[cfg(any(target_os = "macos", test))]
fn parse_scutil_proxy(text: &str) -> Option<String> {
    use std::collections::HashMap;

    let mut fields: HashMap<&str, &str> = HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if !k.is_empty() && !v.is_empty() {
                fields.insert(k, v);
            }
        }
    }

    let enabled = |key: &str| fields.get(key).map(|v| *v == "1").unwrap_or(false);
    let build = |scheme: &str, host_key: &str, port_key: &str| -> Option<String> {
        let host = fields.get(host_key)?;
        if host.is_empty() {
            return None;
        }
        match fields.get(port_key) {
            Some(port) if !port.is_empty() => Some(format!("{scheme}://{host}:{port}")),
            _ => Some(format!("{scheme}://{host}")),
        }
    };

    // Prefer the Secure Web (HTTPS) proxy since vault traffic is TLS by
    // default; a CONNECT proxy is reached over plain HTTP so the URI
    // scheme is `http`. Fall back to the Web (HTTP) proxy, then SOCKS.
    if enabled("HTTPSEnable") {
        if let Some(uri) = build("http", "HTTPSProxy", "HTTPSPort") {
            return Some(uri);
        }
    }
    if enabled("HTTPEnable") {
        if let Some(uri) = build("http", "HTTPProxy", "HTTPPort") {
            return Some(uri);
        }
    }
    if enabled("SOCKSEnable") {
        if let Some(uri) = build("socks5", "SOCKSProxy", "SOCKSPort") {
            return Some(uri);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn platform_proxy_uri() -> Option<String> {
    // GNOME stores the desktop-wide proxy in gsettings. Best-effort
    // only: KDE and other environments use their own stores and fall
    // through to env vars (handled by ureq's default detection).
    let mode = gsettings_get("org.gnome.system.proxy", "mode")?;
    if mode != "manual" {
        // 'none' or 'auto' (PAC) — nothing we can express as a URI.
        return None;
    }
    for (schema, scheme) in [
        ("org.gnome.system.proxy.https", "http"),
        ("org.gnome.system.proxy.http", "http"),
        ("org.gnome.system.proxy.socks", "socks5"),
    ] {
        let host = match gsettings_get(schema, "host") {
            Some(h) if !h.is_empty() => h,
            _ => continue,
        };
        let port = gsettings_get(schema, "port").unwrap_or_default();
        if port.is_empty() || port == "0" {
            return Some(format!("{scheme}://{host}"));
        }
        return Some(format!("{scheme}://{host}:{port}"));
    }
    None
}

/// Read one `gsettings` key, stripping the shell-style quoting gsettings
/// emits (`'host'` → `host`, `uint32 8080` → `8080`).
#[cfg(target_os = "linux")]
fn gsettings_get(schema: &str, key: &str) -> Option<String> {
    let output = std::process::Command::new("gsettings")
        .args(["get", schema, key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let raw = raw.trim();
    // Values come through as `'value'`, `8080`, or `uint32 8080`.
    let raw = raw.rsplit(' ').next().unwrap_or(raw);
    Some(raw.trim_matches('\'').trim().to_string())
}

// Windows: ureq's `win-system-proxy` feature reads the WinINET registry
// directly via its default `Proxy::try_from_env`, so there is nothing to
// add here. Any other platform relies solely on env vars.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_proxy_uri() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scutil_prefers_https_proxy() {
        let text = "<dictionary> {\n  \
            HTTPEnable : 1\n  HTTPProxy : 10.0.0.1\n  HTTPPort : 3128\n  \
            HTTPSEnable : 1\n  HTTPSProxy : 10.0.0.2\n  HTTPSPort : 3129\n  \
            SOCKSEnable : 0\n}";
        assert_eq!(
            parse_scutil_proxy(text),
            Some("http://10.0.0.2:3129".to_string())
        );
    }

    #[test]
    fn scutil_falls_back_to_http_then_socks() {
        let http_only = "HTTPEnable : 1\nHTTPProxy : 10.0.0.1\nHTTPPort : 3128\nHTTPSEnable : 0\nSOCKSEnable : 0\n";
        assert_eq!(
            parse_scutil_proxy(http_only),
            Some("http://10.0.0.1:3128".to_string())
        );

        let socks_only =
            "HTTPEnable : 0\nHTTPSEnable : 0\nSOCKSEnable : 1\nSOCKSProxy : 10.0.0.9\nSOCKSPort : 1080\n";
        assert_eq!(
            parse_scutil_proxy(socks_only),
            Some("socks5://10.0.0.9:1080".to_string())
        );
    }

    #[test]
    fn scutil_no_proxy_returns_none() {
        // The default macOS output when nothing is configured.
        let none = "<dictionary> {\n  FTPPassive : 1\n}";
        assert_eq!(parse_scutil_proxy(none), None);

        // Enabled flag set but no host present is not usable.
        let enabled_no_host = "HTTPSEnable : 1\n";
        assert_eq!(parse_scutil_proxy(enabled_no_host), None);
    }

    #[test]
    fn scutil_omits_port_when_absent() {
        let no_port = "HTTPSEnable : 1\nHTTPSProxy : proxy.local\n";
        assert_eq!(
            parse_scutil_proxy(no_port),
            Some("http://proxy.local".to_string())
        );
    }
}
