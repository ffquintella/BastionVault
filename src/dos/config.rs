//! Configuration for the IP-based DoS / request-abuse guard.
//!
//! A single [`DosConfig`] governs the whole process. It is seeded from the
//! optional `[dos]` startup-config block and then, once an operator edits it
//! through `v2/sys/dos/config`, from the barrier-persisted value (which wins on
//! every subsequent unseal). See `features/dos-abuse-protection.md`.
//!
//! Every numeric limit uses `0` to mean **"this rule is disabled"**, so an
//! operator can turn any single lever off without disabling the whole guard.

use serde::{Deserialize, Serialize};

/// Runtime-adjustable DoS-protection thresholds.
///
/// The model is a fixed window per client IP: within `window_secs`, an IP that
/// issues more than `max_requests` (or more than `auth_max_requests` to
/// authentication paths) is temporarily banned for `ban_secs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DosConfig {
    /// Master switch. When `false` the guard admits every request and records
    /// nothing — enforcement, counting, and auto-bans are all off. Manual bans
    /// added via the API are still stored, but not enforced until re-enabled.
    pub enabled: bool,
    /// Length of the counting window, in seconds.
    pub window_secs: u64,
    /// Maximum requests one IP may make within a window before it is banned.
    /// `0` disables the general rule.
    pub max_requests: u64,
    /// Stricter per-window ceiling applied only to authentication/login paths
    /// (brute-force defense). `0` disables the auth-specific rule.
    pub auth_max_requests: u64,
    /// How long an automatic ban lasts, in seconds. `0` means "count but never
    /// auto-ban" (effectively disables automatic enforcement).
    pub ban_secs: u64,
    /// How often (seconds) each node reloads persisted manual bans from storage
    /// and sweeps expired in-memory state. Governs HA convergence latency for
    /// manual bans. Clamped to a small floor so a misconfiguration cannot
    /// hammer the storage backend.
    pub refresh_secs: u64,
}

impl Default for DosConfig {
    /// Secure-but-non-disruptive defaults: a legitimate operator or client
    /// making a handful of calls per second is never affected, while a flood
    /// from a single IP is stopped within one window.
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 10,
            max_requests: 200,
            auth_max_requests: 20,
            ban_secs: 300,
            refresh_secs: 30,
        }
    }
}

impl DosConfig {
    /// Smallest permitted `refresh_secs`, to bound storage-reload frequency.
    const MIN_REFRESH_SECS: u64 = 5;

    /// Clamp operator-supplied values into a safe, well-defined range. Called
    /// on every `set` so neither the API nor the startup config can install a
    /// degenerate configuration (e.g. a zero-length window).
    pub fn sanitized(mut self) -> Self {
        if self.window_secs == 0 {
            self.window_secs = 1;
        }
        if self.refresh_secs < Self::MIN_REFRESH_SECS {
            self.refresh_secs = Self::MIN_REFRESH_SECS;
        }
        self
    }
}
