//! IP-based DoS / request-abuse protection.
//!
//! The config, the hot-path guard and the barrier-persisted store live in
//! `bv-kernel-api` — [`VaultCtx::dos_guard`](crate::kernel_api::VaultCtx::dos_guard)
//! returns a [`DosGuard`], so the guard is part of the kernel contract and has
//! to sit below it. Everything there is re-exported here, so
//! `bastion_vault::dos::*` paths are unchanged.
//!
//! The actix layer that consults the guard on every request went the other
//! way in Phase 4: it is `bv_server::middleware::dos` now. It could never live
//! below the kernel contract (actix must not reach a leaf engine), and Phase 4
//! gave it somewhere above to go.
//!
//! What stays here is [`store_tests`] — they stand up a whole vault through
//! `crate::test_utils`.
//!
//! Enforcement is per-node in memory; configuration and manual bans persist and
//! converge across an HA cluster via a periodic reload. See
//! `features/dos-abuse-protection.md` for the full model and its bounds, and
//! roadmaps/workspace-decomposition.md § Phase 3 for the split.

pub use bv_kernel_api::dos::{config, guard, store};

pub use config::DosConfig;
pub use guard::{BanInfo, BanKind, BanRecord, DosGuard, DosStats, IpUsage, ManualBan};
pub use store::{DosStore, PersistedDosState};

#[cfg(test)]
mod store_tests;
