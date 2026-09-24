//! Debug-only outbound HTTP(S) proxy override.
//!
//! Compiled **only** when the `debug_proxy` Cargo feature is on, and
//! inert unless `BASTION_DEBUG_PROXY` is also set — the same
//! feature-plus-environment gate the GUI's local MCP bridge uses
//! (AGENTS.md §7, "Local Tauri MCP bridge"). No default build of the
//! server, the CLI, the GUI or any packaged artifact compiles this
//! module, so an operator's machine cannot be talked into routing
//! vault traffic through a proxy by an environment variable alone.
//!
//! What it is for: pointing the desktop GUI at an intercepting HTTP
//! debugger (Charles Proxy, mitmproxy, Fiddler, Burp) so a developer
//! can read the request/response stream between the GUI and a
//! BastionVault server while diagnosing an API problem.
//!
//! **This is an MITM by construction.** Every request the process
//! makes — including the bearer token in `X-Vault-Token` and every
//! secret in a response body — is readable in cleartext by whoever
//! runs the proxy. It is for scratch/dev vaults only. Nothing here is
//! silent: resolution logs at WARN once per process, naming the proxy
//! and the TLS posture, so a session running through a proxy is
//! obvious in the log.
//!
//! ## Environment
//!
//! | Variable | Meaning |
//! |---|---|
//! | `BASTION_DEBUG_PROXY` | Proxy URI — `http://127.0.0.1:8888` (Charles' default), `socks5://…`. Unset ⇒ module inert. |
//! | `BASTION_DEBUG_PROXY_CA` | Path to the proxy's root CA in PEM form. Becomes the **only** trusted root, so the MITM certificate validates normally. |
//! | `BASTION_DEBUG_PROXY_INSECURE` | `1`/`true`/`yes` ⇒ disable TLS verification outright. Mutually exclusive with `_CA`, which it overrides (with a warning). |
//!
//! With neither `_CA` nor `_INSECURE`, the caller's own TLS settings
//! are left untouched: an HTTPS target will fail the handshake against
//! the proxy's certificate, which is the correct, loud failure rather
//! than a silent downgrade.

use std::{fs, sync::Arc, sync::OnceLock};

use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};

/// A resolved debug-proxy override. Obtained from [`active`].
pub struct DebugProxy {
    /// The URI exactly as the operator wrote it, for logging.
    pub uri: String,
    /// The proxy to install on the `ureq` agent.
    pub proxy: ureq::Proxy,
    /// TLS override, when the operator supplied a CA or asked for
    /// verification to be disabled. `None` leaves the caller's own TLS
    /// configuration in place.
    pub tls: Option<TlsConfig>,
}

const ENV_URI: &str = "BASTION_DEBUG_PROXY";
const ENV_CA: &str = "BASTION_DEBUG_PROXY_CA";
const ENV_INSECURE: &str = "BASTION_DEBUG_PROXY_INSECURE";

static RESOLVED: OnceLock<Option<DebugProxy>> = OnceLock::new();

/// The active debug proxy, or `None` when `BASTION_DEBUG_PROXY` is
/// unset or unusable.
///
/// Resolved once per process: the environment is read on the first
/// call and the outcome — including the WARN banner — is reused by
/// every agent built afterwards, so a long-lived GUI session logs the
/// interception once rather than on every connection.
pub fn active() -> Option<&'static DebugProxy> {
    RESOLVED.get_or_init(resolve).as_ref()
}

fn resolve() -> Option<DebugProxy> {
    let uri = non_empty(ENV_URI)?;

    let proxy = match ureq::Proxy::new(&uri) {
        Ok(p) => p,
        Err(e) => {
            log::error!("{ENV_URI}='{uri}' is not a usable proxy URI ({e}); ignoring it");
            return None;
        }
    };

    let insecure = env_flag(ENV_INSECURE);
    let ca_path = non_empty(ENV_CA);

    let tls = if insecure {
        if ca_path.is_some() {
            log::warn!("{ENV_INSECURE} is set; ignoring {ENV_CA}");
        }
        Some(TlsConfig::builder().disable_verification(true).build())
    } else if let Some(path) = &ca_path {
        match load_ca(path) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                log::error!("cannot use {ENV_CA}='{path}' ({e}); debug proxy disabled");
                return None;
            }
        }
    } else {
        None
    };

    let posture = match (&tls, insecure) {
        (_, true) => "TLS VERIFICATION DISABLED",
        (Some(_), _) => "trusting only the CA from $BASTION_DEBUG_PROXY_CA",
        (None, _) => "TLS unchanged — an HTTPS target will fail the handshake \
                      unless the proxy CA is already trusted; set \
                      $BASTION_DEBUG_PROXY_CA or $BASTION_DEBUG_PROXY_INSECURE",
    };
    log::warn!(
        "DEBUG PROXY ACTIVE: routing all outbound vault HTTP(S) through '{uri}' ({posture}). \
         Tokens and secrets are visible to that proxy — never use this against a real vault."
    );

    Some(DebugProxy { uri, proxy, tls })
}

/// Build a TLS config whose only trusted root is the proxy's CA. The
/// set is deliberately *replaced* rather than extended: a debug run
/// should reach the proxy and nothing else, and a typo'd PEM then
/// fails loudly instead of quietly falling back to the system roots.
fn load_ca(path: &str) -> Result<TlsConfig, String> {
    let pem = fs::read(path).map_err(|e| e.to_string())?;
    let roots: Vec<Certificate<'static>> = ureq::tls::parse_pem(&pem)
        .filter_map(|item| match item {
            Ok(PemItem::Certificate(cert)) => Some(cert),
            _ => None,
        })
        .collect();
    if roots.is_empty() {
        return Err("no CERTIFICATE block found in the PEM".to_string());
    }
    Ok(TlsConfig::builder()
        .root_certs(RootCerts::Specific(Arc::new(roots)))
        .build())
}

fn non_empty(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_flag(var: &str) -> bool {
    non_empty(var)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_ca_rejects_a_pem_without_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-ca.pem");
        fs::write(&path, b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
            .unwrap();
        let err = load_ca(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("no CERTIFICATE block"), "{err}");
    }

    #[test]
    fn load_ca_reports_a_missing_file() {
        let err = load_ca("/nonexistent/charles-root.pem").unwrap_err();
        assert!(!err.is_empty());
    }
}
