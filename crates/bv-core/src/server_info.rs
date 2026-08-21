//! Process-wide server identity + lifecycle facts.
//!
//! `started_at()` returns the timestamp the running process started
//! tracking this value — set explicitly by `record_start_now()` from
//! the HTTP server or embedded-GUI startup paths, or lazily on first
//! access (which is good enough for "uptime since first request" if
//! the explicit hook ever gets skipped).
//!
//! There is deliberately no `version()` here. The version an operator
//! reads out of `/sys/info` or the GUI's Server Info dialog has to be
//! the *product* version — the one `bvault --version` prints and the one
//! on the installer — and `env!("CARGO_PKG_VERSION")` in this file
//! expands to *this crate's* library version instead, which moves by
//! content rather than by release (AGENTS.md §7). That mismatch shipped:
//! a 0.41.9 server reported 0.41.1, because that is where `bv-core`
//! happened to be. The single source is `bastion_vault::VERSION`.

use std::sync::OnceLock;

use chrono::{DateTime, Utc};

static STARTED_AT: OnceLock<DateTime<Utc>> = OnceLock::new();
static API_ADDR: OnceLock<String> = OnceLock::new();
static PEER_CA_FILE: OnceLock<String> = OnceLock::new();

/// Record "now" as the server start time. Idempotent — a second call
/// is a no-op so callers don't need to coordinate (HTTP server +
/// embedded GUI both attempt this at their respective startup paths).
pub fn record_start_now() {
    let _ = STARTED_AT.set(Utc::now());
}

pub fn started_at() -> DateTime<Utc> {
    *STARTED_AT.get_or_init(Utc::now)
}

pub fn uptime_seconds() -> i64 {
    (Utc::now() - started_at()).num_seconds().max(0)
}

/// Record this node's externally reachable API base URL — the `api_addr`
/// config value (e.g. `https://bv-1.corp.example:8200`).
///
/// The listener address alone cannot serve this purpose: it is routinely
/// `0.0.0.0:<port>`, which no peer can dial. Cluster features that need to
/// reach *this* node from another one — currently the cross-node backup fetch
/// behind a scheduled-backup restore — stamp this value into replicated
/// metadata so the other nodes know where to call. Idempotent; first call
/// wins.
pub fn record_api_addr(addr: &str) {
    let addr = addr.trim();
    if addr.is_empty() {
        return;
    }
    let _ = API_ADDR.set(addr.trim_end_matches('/').to_string());
}

/// This node's advertised API base URL, or `None` when the config does not
/// set `api_addr` (embedded GUI vaults, single-node deployments that never
/// need to be dialled by a peer).
pub fn api_addr() -> Option<&'static str> {
    API_ADDR.get().map(|s| s.as_str())
}

/// Record a PEM file to use as the trust anchor when this node dials a
/// cluster peer. Sourced from the listener's `tls_publish_ca_path` — the
/// certificate the operator already publishes for local clients — which is
/// what a private-CA or self-signed cluster needs. Unset means peer
/// connections verify against the platform trust store.
pub fn record_peer_ca_file(path: &str) {
    let path = path.trim();
    if path.is_empty() {
        return;
    }
    let _ = PEER_CA_FILE.set(path.to_string());
}

pub fn peer_ca_file() -> Option<&'static str> {
    PEER_CA_FILE.get().map(|s| s.as_str())
}
