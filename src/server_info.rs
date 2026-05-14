//! Process-wide server identity + lifecycle facts.
//!
//! `started_at()` returns the timestamp the running process started
//! tracking this value — set explicitly by `record_start_now()` from
//! the HTTP server or embedded-GUI startup paths, or lazily on first
//! access (which is good enough for "uptime since first request" if
//! the explicit hook ever gets skipped). `version()` returns the
//! Cargo-baked crate version so both the HTTP `/sys/info` endpoint
//! and the GUI's Server Info dialog read from a single source.

use std::sync::OnceLock;

use chrono::{DateTime, Utc};

static STARTED_AT: OnceLock<DateTime<Utc>> = OnceLock::new();

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

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
