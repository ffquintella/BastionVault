//! IP-based DoS / request-abuse protection.
//!
//! A configurable, per-client-IP request guard that temporarily bans IPs which
//! exceed a request-rate threshold, with a stricter sub-limit for
//! authentication paths (brute-force defense). Operators manage it from the
//! GUI Settings "Abuse Protection" panel over `v2/sys/dos/*`.
//!
//! Layout:
//! - [`config`] — the runtime-adjustable [`DosConfig`] thresholds.
//! - [`guard`] — the in-memory [`DosGuard`] hot-path enforcer (per node).
//! - [`store`] — barrier-persisted config + manual bans (survive restart, HA).
//! - [`middleware`] — the actix layer that consults the guard on every request.
//!
//! Enforcement is per-node in memory; configuration and manual bans persist and
//! converge across an HA cluster via a periodic reload. See
//! `features/dos-abuse-protection.md` for the full model and its bounds.

pub mod config;
pub mod guard;
pub mod middleware;
pub mod store;

pub use config::DosConfig;
pub use guard::{BanInfo, BanKind, BanRecord, DosGuard, DosStats, IpUsage, ManualBan};
pub use store::{DosStore, PersistedDosState};
